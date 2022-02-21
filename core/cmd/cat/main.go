package main

// This is a small utility that acts like cat(1), see `man 1 cat`
// Primarily used by emp3r0r's C2 UI

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig)

	go func() {
		for {
			s := <-sig
			// ignore any signals except SIGTERM
			// (and SIGKILL that cannot be ignored)
			if s == syscall.SIGTERM {
				log.Fatal("Terminated")
			}
		}
	}()

	// copies everything from stdin to stdout
	// if any error occurs, abort
	for {
		// loop forever, in case the user sends us a fucking EOF/Ctrl-D
		// io.Copy aborts on EOF
		_, err := io.Copy(os.Stdin, os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
	}
}
