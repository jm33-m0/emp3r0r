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
)

// GetConnectedAgents returns snapshots of every agent in the registry. The
// result is safe to serialize and never aliases a registry record.
func GetConnectedAgents() []*def.Emp3r0rAgent {
	var agents []*def.Emp3r0rAgent
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		agents = append(agents, SnapshotAgent(rec.Agent))
		return true
	})
	return agents
}

// GetAgentByIndex returns the agent assigned control index, or nil if no agent
// holds it. Only the C2 server assigns indices, so this always returns nil in
// the operator process.
func GetAgentByIndex(index int) (target *def.Emp3r0rAgent) {
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		if rec.Control != nil && rec.Control.Index == index {
			target = SnapshotAgent(rec.Agent)
			return false // stop iteration
		}
		return true
	})
	return target
}

// GetAgentByTag returns a snapshot of the agent with the given tag, or nil.
func GetAgentByTag(tag string) (target *def.Emp3r0rAgent) {
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		if rec.Agent.Tag == tag {
			target = SnapshotAgent(rec.Agent)
			return false // stop iteration
		}
		return true
	})
	return target
}

// GetAgentByUUID returns a snapshot of the agent with the given UUID, or nil.
func GetAgentByUUID(uuid string) (target *def.Emp3r0rAgent) {
	if rec, ok := live.LookupAgent(uuid); ok {
		return SnapshotAgent(rec.Agent)
	}
	return nil
}

// IsAgentExistByUUID is agent already in target list?
func IsAgentExistByUUID(uuid string) bool {
	_, ok := live.LookupAgent(uuid)
	return ok
}

// SendMessageToAgent send MsgTunData to agent
func SendMessageToAgent(msg_data *def.MsgTunData, agent *def.Emp3r0rAgent) (err error) {
	if agent == nil {
		return fmt.Errorf("Send2Agent (%s): agent is nil", msg_data.CmdSlice)
	}
	rec, ok := live.LookupAgent(agent.UUID)
	if !ok || rec.Control == nil || rec.Control.Conn == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", msg_data.CmdSlice)
	}
	out := cbor.NewEncoder(rec.Control.Conn)
	return out.Encode(msg_data)
}

// SetActiveAgent set the active agent as the target
func SetActiveAgent(identifier string) {
	parsedArgs := util.ParseCmd(identifier)
	if len(parsedArgs) == 0 {
		logging.Errorf("Target does not exist, no target has been selected")
		return
	}
	target := parsedArgs[0]
	var targetToSet *def.Emp3r0rAgent

	// select by tag or index
	targetToSet = GetAgentByTag(target)
	if targetToSet == nil {
		index, e := strconv.Atoi(target)
		if e == nil {
			targetToSet = GetAgentByIndex(index)
		}
	}

	if targetToSet == nil {
		logging.Errorf("Target does not exist, no target has been selected")
		return
	}
	live.SetActiveAgent(targetToSet)
}

// IsAgentExistByTag is agent already in target list?
func IsAgentExistByTag(tag string) bool {
	return GetAgentByTag(tag) != nil
}

// IsAgentExist is agent already in target list?
func IsAgentExist(t *def.Emp3r0rAgent) bool {
	if t == nil {
		return false
	}
	return IsAgentExistByUUID(t.UUID)
}

// AssignAgentIndex assign an unused index number to a new agent.
func AssignAgentIndex() (index int) {
	// loop thru agent list and get all index numbers
	indexList := make([]int, 0)
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		if rec.Control != nil {
			indexList = append(indexList, rec.Control.Index)
		}
		return true
	})

	// index is 0 for the first agent
	if len(indexList) == 0 {
		return 0
	}

	sort.Ints(indexList)

	// find the smallest unused number in [0, len)
	for i, used := range indexList {
		if used != i {
			return i
		}
	}
	return len(indexList)
}
