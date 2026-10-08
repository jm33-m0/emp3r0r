package relay

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// WgFileServer serves a file over HTTP on the userspace WireGuard stack.
func WgFileServer(path_to_file string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(wrt http.ResponseWriter, req *http.Request) {
		http.ServeFile(wrt, req, path_to_file)
	})
	listenAddr := fmt.Sprintf("%s:%d", wireguard.WgServerIP, wireguard.WgFileServerPort)

	// Retry until the userspace WireGuard stack is ready to accept listeners.
	var lastErr error
	for i := range 100 {
		ln, err := wireguard.Listen("tcp", listenAddr)
		if err != nil {
			lastErr = err
			// Suppress the error message for the first few seconds.
			if i > 5 {
				logging.Warningf("WgFileServer: failed to listen on %s, retrying: %v", listenAddr, err)
			}
			time.Sleep(time.Second)
			continue
		}
		logging.Infof("WgFileServer: serving %s on %s", path_to_file, listenAddr)
		return http.Serve(ln, mux)
	}

	return fmt.Errorf("WgFileServer: failed to listen on %s after 100 attempts: %w", listenAddr, lastErr)
}
