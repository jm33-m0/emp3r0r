package operator

import (
	"net/url"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// c2AddressCompletions returns useful --cc values: the configured C2 address,
// certificate names, and the explicit http(s) forms. Supplying the host both
// bare and with a scheme makes the TLS/front-proxy choice discoverable while
// typing.
func c2AddressCompletions() []string {
	var values []string
	seen := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSuffix(strings.TrimSpace(value), "/")
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}

	var hosts []string
	addHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		for _, existing := range hosts {
			if existing == host {
				return
			}
		}
		hosts = append(hosts, host)
	}

	if configured := strings.TrimSuffix(live.RuntimeConfig.CCAddress, "/"); configured != "" {
		if strings.Contains(configured, "://") {
			add(configured)
			if u, err := url.Parse(configured); err == nil {
				addHost(u.Hostname())
			}
		} else {
			addHost(configured)
		}
	}
	for _, host := range transport.NamesInCert(transport.ServerCrtFile) {
		addHost(host)
	}

	for _, host := range hosts {
		add(host)
		add("https://" + host)
		add("http://" + host)
		if live.RuntimeConfig.CCH2Port != "" {
			add("https://" + host + ":" + live.RuntimeConfig.CCH2Port)
		}
		if live.RuntimeConfig.CCHTTPPort != "" {
			add("http://" + host + ":" + live.RuntimeConfig.CCHTTPPort)
		}
	}
	return values
}

// c2PortCompletions suggests the configured polling/TLS ports and common
// front-proxy ports for --cc-http-port.
func c2PortCompletions() []string {
	var values []string
	seen := make(map[string]struct{})
	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}

	add(live.RuntimeConfig.CCHTTPPort)
	add(live.RuntimeConfig.CCH2Port)
	add("80")
	add("443")
	add("8080")
	add("8443")
	return values
}
