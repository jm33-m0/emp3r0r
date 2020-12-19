package main

import (
	"flag"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/agent"
	"github.com/jm33-m0/emp3r0r/core/internal/cc"
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

func main() {
	go cc.TLSServer()

	cdnproxy := flag.String("cdn2proxy", "", "Start cdn2proxy server on this port")
	flag.Parse()

	if *cdnproxy != "" {
		go func() {
			logFile, err := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				log.Fatal(err)
			}
			err = cdn2proxy.StartServer(*cdnproxy, "127.0.0.1:"+agent.CCPort, logFile)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	err := cc.CliBanner()
	if err != nil {
		log.Fatal(err)
	}

	cc.CliMain()
}
