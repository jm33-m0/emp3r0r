package relay

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

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
