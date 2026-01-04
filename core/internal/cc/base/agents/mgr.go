package agents

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// GetConnectedAgents returns a slice of connected emp3r0r agents.
func GetConnectedAgents() []*def.Emp3r0rAgent {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	agents := make([]*def.Emp3r0rAgent, 0, len(live.AgentControlMap))
	for agent := range live.AgentControlMap {
		agents = append(agents, agent)
	}
	return agents
}

// GetAgentByIndex find target from def.AgentControlMap via control index, return nil if not found
func GetAgentByIndex(index int) (target *def.Emp3r0rAgent) {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	for t, ctl := range live.AgentControlMap {
		if ctl.Index == index {
			target = t
			break
		}
	}
	return
}

// GetAgentByTag find target from def.AgentControlMap via tag, return nil if not found
func GetAgentByTag(tag string) (target *def.Emp3r0rAgent) {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	for t := range live.AgentControlMap {
		if t.Tag == tag {
			target = t
			break
		}
	}
	if target == nil {
		for _, t := range live.AgentList {
			if t.Tag == tag {
				target = t
				break
			}
		}
	}
	return
}

// GetTargetFromH2Conn find target from def.AgentControlMap via HTTP2 connection ID, return nil if not found
func GetTargetFromH2Conn(conn *h2conn.Conn) (target *def.Emp3r0rAgent) {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	for t, ctrl := range live.AgentControlMap {
		if conn == ctrl.Conn {
			target = t
			break
		}
	}
	return
}

// SendMessageToAgent send MsgTunData to agent
func SendMessageToAgent(msg_data *def.MsgTunData, agent *def.Emp3r0rAgent) (err error) {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	ctrl := live.AgentControlMap[agent]
	if ctrl == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", msg_data.CmdSlice)
	}
	if ctrl.Conn == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", msg_data.CmdSlice)
	}
	out := cbor.NewEncoder(ctrl.Conn)

	err = out.Encode(msg_data)
	return
}

// SetActiveAgent set the active agent as the target
func SetActiveAgent(identifier string) {
	parsedArgs := util.ParseCmd(identifier)
	target := parsedArgs[0]
	var target_to_set *def.Emp3r0rAgent

	// select by tag or index
	target_to_set = GetAgentByTag(target)
	if target_to_set == nil {
		index, e := strconv.Atoi(target)
		if e == nil {
			target_to_set = GetAgentByIndex(index)
		}
	}

	if target_to_set == nil {
		// if still nothing
		logging.Errorf("Target does not exist, no target has been selected")
		return
	} else {
		live.ActiveAgent = target_to_set
	}
}

// IsAgentExistByTag is agent already in target list?
func IsAgentExistByTag(tag string) bool {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	for a := range live.AgentControlMap {
		if a.Tag == tag {
			return true
		}
	}

	return false
}

// IsAgentExist is agent already in target list?
func IsAgentExist(t *def.Emp3r0rAgent) bool {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	return IsAgentExistLocked(t)
}

// IsAgentExistLocked checks if agent exists (caller must hold lock)
func IsAgentExistLocked(t *def.Emp3r0rAgent) bool {
	for a := range live.AgentControlMap {
		if a.Tag == t.Tag {
			return true
		}
	}
	return false
}

// AssignAgentIndex assign an index number to new agent
func AssignAgentIndex() (index int) {
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	return AssignAgentIndexLocked()
}

// AssignAgentIndexLocked assigns index (caller must hold lock)
func AssignAgentIndexLocked() (index int) {
	// index is 0 for the first agent
	if len(live.AgentControlMap) == 0 {
		return 0
	}

	// loop thru agent list and get all index numbers
	index_list := make([]int, 0)
	for _, c := range live.AgentControlMap {
		index_list = append(index_list, c.Index)
	}

	// sort
	sort.Ints(index_list)

	// find available numbers
	available_indexes := make([]int, 0)
	for i := 0; i < len(index_list); i++ {
		if index_list[i] != i {
			available_indexes = append(available_indexes, i)
		}
	}
	if len(available_indexes) == 0 {
		return len(index_list)
	}

	// use the smallest available number
	return available_indexes[0]
}
