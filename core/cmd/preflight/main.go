package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
)

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request from %s", r.RemoteAddr)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Read error", http.StatusBadRequest)
			return
		}
		resp, err := preflight.ProcessRequest(body, true)
		if err != nil {
			log.Printf("Preflight failed: %v", err)
			http.Error(w, "Preflight failed", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	})

	log.Printf("Starting standalone Preflight server on :%s", *port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", *port), nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
