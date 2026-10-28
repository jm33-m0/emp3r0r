// Command tor-bridge relays Tor hidden-service connections to the C2 bridge
// socket. Point the hidden service at --listen.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jm33-m0/emp3r0r/core/pkg/transportbridge"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "local address the Tor hidden service forwards to")
	socket := flag.String("c2-socket", "", "C2 bridge Unix socket")
	transport := flag.String("transport", "tor", "transport name shared with the agent dialer")
	flag.Parse()
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "--c2-socket is required")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := transportbridge.ServeTCP(ctx, *listen, transportbridge.Config{
		Transport: *transport,
		C2Socket:  *socket,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
