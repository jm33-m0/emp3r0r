package server

import (
	"fmt"
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartC2H2StreamServer starts the h2 stream transport server.
// TLS is owned by the TLS layer; this server only handles HTTP/h2 stream routing.
func StartC2H2StreamServer() {
	channelWrapper, err := transport.GetC2ChannelWrapper(def.C2ChannelModeH2Conn)
	if err != nil {
		logging.Fatalf("StartC2H2StreamServer: resolve %q wrapper: %v", def.C2ChannelModeH2Conn, err)
	}

	mux := http.NewServeMux()
	registerPreflightFeature(mux)
	registerC2H2StreamAcceptHandler(mux, channelWrapper)

	listener := setupC2TLSListener()
	network.EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", live.RuntimeConfig.CCPort),
		Handler: mux,
	}

	logging.Successf("🚀 Starting C2 h2 stream server with TLS at port %s", live.RuntimeConfig.CCPort)
	if err = network.EmpTLSServer.Serve(listener); err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 h2 stream server is shutdown")
			return
		}
		logging.Fatalf("Failed to start C2 h2 stream server at *:%s: %v", live.RuntimeConfig.CCPort, err)
	}
}

func registerC2H2StreamAcceptHandler(mux *http.ServeMux, channelWrapper transport.C2ChannelWrapper) {
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			logging.Debugf("cborStreamAccept: rejecting non-stream request method=%s path=%s from %s", req.Method, req.URL.Path, req.RemoteAddr)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		conn, err := channelWrapper.Accept(w, req)
		if err != nil {
			logging.Errorf("cborStreamAccept: channel accept failed from %s: %v", req.RemoteAddr, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		stream := transport.NewStreamTransport(conn, req.RemoteAddr)
		cborStreamAccept(stream)
	})
}
