package main

import (
	"log"

	"github.com/jm33-m0/emp3r0r/emagent/internal/cc"
)

func main() {
	go cc.TLSServer()

	err := cc.CliBanner()
	if err != nil {
		log.Fatal(err)
	}
	cc.CliMain()
}
