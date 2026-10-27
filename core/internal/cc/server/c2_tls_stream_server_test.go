package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

type fakeH2Wrapper struct {
	accepted chan struct{}
}

func (f *fakeH2Wrapper) Dial(context.Context, *http.Client, string) (io.ReadWriteCloser, *http.Response, error) {
	return nil, nil, errors.New("not used")
}

func (f *fakeH2Wrapper) Accept(http.ResponseWriter, *http.Request) (io.ReadWriteCloser, error) {
	f.accepted <- struct{}{}
	return eofReadWriteCloser{}, nil
}

type eofReadWriteCloser struct{}

func (eofReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (eofReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (eofReadWriteCloser) Close() error                { return nil }

func tlsTestConfig() *def.Config {
	return &def.Config{
		MalleableC2: def.MalleableHTTPConfig{
			C2Path:        "/poll",
			SessionHeader: "X-Session",
			SessionValue:  "s=%s",
			InitHeader:    "X-Init",
			InitValue:     "1",
			CloseHeader:   "X-Close",
			CloseValue:    "1",
		},
	}
}

func tlsTestRequest(t *testing.T, client *http.Client, method, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestC2TLSFrontendRoutesHTTPPoll(t *testing.T) {
	previous := live.GetRuntimeConfig()
	live.SetRuntimeConfig(tlsTestConfig())
	t.Cleanup(func() { live.SetRuntimeConfig(previous) })

	server := httptest.NewServer(newC2TLSHandler(nil, errors.New("h2 disabled")))
	defer server.Close()

	resp := tlsTestRequest(t, server.Client(), http.MethodPost, server.URL+"/poll", map[string]string{
		"X-Session": "tls-poll-session",
		"X-Init":    "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http_poll init over TLS frontend = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = tlsTestRequest(t, server.Client(), http.MethodPost, server.URL+"/wrong", map[string]string{
		"X-Session": "tls-poll-session",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("http_poll wrong path = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	resp = tlsTestRequest(t, server.Client(), http.MethodPost, server.URL+"/poll", map[string]string{
		"X-Session": "tls-poll-session",
		"X-Close":   "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http_poll close over TLS frontend = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestC2TLSFrontendRoutesH2Conn(t *testing.T) {
	previous := live.GetRuntimeConfig()
	live.SetRuntimeConfig(tlsTestConfig())
	t.Cleanup(func() { live.SetRuntimeConfig(previous) })

	h2 := &fakeH2Wrapper{accepted: make(chan struct{}, 1)}
	server := httptest.NewServer(newC2TLSHandler(h2, nil))
	defer server.Close()

	resp := tlsTestRequest(t, server.Client(), http.MethodPost, server.URL+"/", nil)
	resp.Body.Close()
	select {
	case <-h2.accepted:
	default:
		t.Fatal("sessionless POST was not routed to h2conn")
	}

	resp = tlsTestRequest(t, server.Client(), http.MethodGet, server.URL+"/", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("browser GET over TLS frontend = %d, want 405", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestC2TLSFrontendRoutesHTTPPollBeforeH2Conn(t *testing.T) {
	previous := live.GetRuntimeConfig()
	live.SetRuntimeConfig(tlsTestConfig())
	t.Cleanup(func() { live.SetRuntimeConfig(previous) })

	h2 := &fakeH2Wrapper{accepted: make(chan struct{}, 1)}
	server := httptest.NewServer(newC2TLSHandler(h2, nil))
	defer server.Close()

	resp := tlsTestRequest(t, server.Client(), http.MethodPost, server.URL+"/poll", map[string]string{
		"X-Session": "tls-routing-session",
		"X-Init":    "1",
	})
	resp.Body.Close()
	select {
	case <-h2.accepted:
		t.Fatal("http_poll request was routed to h2conn")
	default:
	}
}

var _ transport.C2ChannelWrapper = (*fakeH2Wrapper)(nil)
