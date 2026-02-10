package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
)

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logging.Debugf("Received request from %s", r.RemoteAddr)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Read error", http.StatusBadRequest)
			return
		}
		resp, err := preflight.ProcessRequest(body, true)
		if err != nil {
			logging.Errorf("Preflight failed: %v", err)
			http.Error(w, "Preflight failed", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	})

	logging.Infof("Starting standalone Preflight server on :%s", *port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", *port), nil); err != nil {
		logging.Fatalf("Server failed: %v", err)
	}
}
