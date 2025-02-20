package agents

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
	"github.com/spf13/cobra"
)

// GetConnectedAgents returns a slice of connected emp3r0r agents.
func GetConnectedAgents() []*emp3r0r_def.Emp3r0rAgent {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	agents := make([]*emp3r0r_def.Emp3r0rAgent, 0, len(def.AgentControlMap))
	for agent := range def.AgentControlMap {
		agents = append(agents, agent)
	}
	return agents
}

// GetAgentByIndex find target from def.AgentControlMap via control index, return nil if not found
func GetAgentByIndex(index int) (target *emp3r0r_def.Emp3r0rAgent) {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	for t, ctl := range def.AgentControlMap {
		if ctl.Index == index {
			target = t
			break
		}
	}
	return
}

// GetAgentByTag find target from def.AgentControlMap via tag, return nil if not found
func GetAgentByTag(tag string) (target *emp3r0r_def.Emp3r0rAgent) {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	for t := range def.AgentControlMap {
		if t.Tag == tag {
			target = t
			break
		}
	}
	return
}

// GetTargetFromH2Conn find target from def.AgentControlMap via HTTP2 connection ID, return nil if not found
func GetTargetFromH2Conn(conn *h2conn.Conn) (target *emp3r0r_def.Emp3r0rAgent) {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	for t, ctrl := range def.AgentControlMap {
		if conn == ctrl.Conn {
			target = t
			break
		}
	}
	return
}

// SendMessageToAgent send MsgTunData to agent
func SendMessageToAgent(msg_data *emp3r0r_def.MsgTunData, agent *emp3r0r_def.Emp3r0rAgent) (err error) {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	ctrl := def.AgentControlMap[agent]
	if ctrl == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", msg_data.CmdSlice)
	}
	if ctrl.Conn == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", msg_data.CmdSlice)
	}
	out := json.NewEncoder(ctrl.Conn)

	err = out.Encode(msg_data)
	return
}

// CmdSetActiveAgent set the active agent as the target
func CmdSetActiveAgent(cmd *cobra.Command, args []string) {
	parsedArgs := util.ParseCmd(args[0])
	target := parsedArgs[0]
	var target_to_set *emp3r0r_def.Emp3r0rAgent

	// select by tag or index
	target_to_set = GetAgentByTag(target)
	if target_to_set == nil {
		index, e := strconv.Atoi(target)
		if e == nil {
			target_to_set = GetAgentByIndex(index)
		}
	}

	select_agent := func(a *emp3r0r_def.Emp3r0rAgent) {
		def.ActiveAgent = a
		logging.Successf("Now targeting %s", def.ActiveAgent.Tag)
		logging.Printf("Run `file_manager` to open a SFTP session")
		// autoCompleteAgentExes(target_to_set)
	}

	if target_to_set == nil {
		// if still nothing
		logging.Errorf("Target does not exist, no target has been selected")
		return

	} else {
		// lets start the bash shell
		go select_agent(target_to_set)
	}
}

// IsAgentExistByTag is agent already in target list?
func IsAgentExistByTag(tag string) bool {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	for a := range def.AgentControlMap {
		if a.Tag == tag {
			return true
		}
	}

	return false
}

// IsAgentExist is agent already in target list?
func IsAgentExist(t *emp3r0r_def.Emp3r0rAgent) bool {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()
	for a := range def.AgentControlMap {
		if a.Tag == t.Tag {
			return true
		}
	}

	return false
}

// AssignAgentIndex assign an index number to new agent
func AssignAgentIndex() (index int) {
	def.AgentControlMapMutex.RLock()
	defer def.AgentControlMapMutex.RUnlock()

	// index is 0 for the first agent
	if len(def.AgentControlMap) == 0 {
		return 0
	}

	// loop thru agent list and get all index numbers
	index_list := make([]int, 0)
	for _, c := range def.AgentControlMap {
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
