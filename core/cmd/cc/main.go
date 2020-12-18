package main

import (
	"flag"
	"log"

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
			err := cdn2proxy.StartServer(*cdnproxy, "127.0.0.1:"+agent.CCPort, true)
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
