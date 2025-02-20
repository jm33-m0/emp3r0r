package main

import (
	"flag"
	"log"

	"github.com/jm33-m0/emp3r0r/core/internal/listener"
)

func main() {
	stagerPath := flag.String("stager", "", "path to the stager file to serve")
	port := flag.String("port", "8080", "port to serve the stager file on")
	keyStr := flag.String("key", "my_secret_key", "key to encrypt the stager file")
	plain_http := flag.Bool("plain", false, "serve stager file over plain HTTP")
	flag.Parse()

	if *stagerPath == "" {
		log.Fatal("stager file path is required")
	}

	if *plain_http {
		listener.HTTPBareListener(*stagerPath, *port)
		return
	}
	listener.HTTPAESCompressedListener(*stagerPath, *port, *keyStr, true)
}
