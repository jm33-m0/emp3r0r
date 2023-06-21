package tun

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// https://tools.ietf.org/html/rfc7231#section-4.3.6
// Conceivably we could also proxy over HTTP/2:
// https://httpwg.org/specs/rfc7540.html#CONNECT
// https://github.com/caddyserver/forwardproxy/blob/05b2092e07f9d10b3803d8fb9775d2f87dc58590/httpclient/httpclient.go

type httpProxy struct {
	network, addr string
	auth          *proxy.Auth
	forward       proxy.Dialer
}

func (pr *httpProxy) Dial(network, addr string) (net.Conn, error) {
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	// http.Transport has a ProxyConnectHeader field that we are ignoring
	// here.
	if pr.auth != nil {
		connectReq.Header.Set("Proxy-Authorization", "basic "+
			base64.StdEncoding.EncodeToString([]byte(pr.auth.User+":"+pr.auth.Password)))
	}

	conn, err := pr.forward.Dial(pr.network, pr.addr)
	if err != nil {
		return nil, err
	}

	err = connectReq.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The Go stdlib says: "Okay to use and discard buffered reader here,
	// because TLS server will not speak until spoken to."
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if br.Buffered() != 0 {
		panic(br.Buffered())
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy server returned %q", resp.Status)
	}

	return conn, nil
}

func ProxyHTTP(network, addr string, auth *proxy.Auth, forward proxy.Dialer) (*httpProxy, error) {
	return &httpProxy{
		network: network,
		addr:    addr,
		auth:    auth,
		forward: forward,
	}, nil
}

type UTLSDialer struct {
	config        *utls.Config
	clientHelloID *utls.ClientHelloID
	forward       proxy.Dialer
}

func (dialer *UTLSDialer) Dial(network, addr string) (net.Conn, error) {
	return dialUTLS(network, addr, dialer.config, dialer.clientHelloID, dialer.forward)
}

func ProxyHTTPS(network, addr string, auth *proxy.Auth, forward proxy.Dialer, cfg *utls.Config, clientHelloID *utls.ClientHelloID) (*httpProxy, error) {
	return &httpProxy{
		network: network,
		addr:    addr,
		auth:    auth,
		forward: &UTLSDialer{
			config: cfg,
			// We use the same uTLS ClientHelloID for the TLS
			// connection to the HTTPS proxy, as we use for the TLS
			// connection through the tunnel.
			clientHelloID: clientHelloID,
			forward:       forward,
		},
	}, nil
}
