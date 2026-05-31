package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// LabeledAgent stores agent custom label info to a file.
type LabeledAgent struct {
	Tag   string `json:"tag"`
	Label string `json:"label"`
}

// AgentsJSON is the filename for storing agent labels.
const AgentsJSON = "agents.json"

// PersistLabeledAgentsToFile saves custom labels to a file.
func PersistLabeledAgentsToFile() {
	var (
		labeledAgents []LabeledAgent
		old           []LabeledAgent
	)
	if util.IsExist(AgentsJSON) {
		data, readErr := os.ReadFile(AgentsJSON)
		if readErr == nil {
			_ = json.Unmarshal(data, &old)
		}
	}
	live.AgentControlMap.Range(func(tag, control any) bool {
		t := tag.(*def.Emp3r0rAgent)
		c := control.(*live.AgentControl)
		if c.Label == "" {
			return true
		}
		labeled := &LabeledAgent{
			Tag:   t.Tag,
			Label: c.Label,
		}
		for i, l := range old {
			if l.Tag == labeled.Tag {
				old[i].Label = labeled.Label // update label
				old[i] = l
				return true // continue outter loop (simulated by returning true)
			}
		}
		labeledAgents = append(labeledAgents, *labeled)
		return true
	})
	labeledAgents = append(labeledAgents, old...)
	if len(labeledAgents) == 0 {
		return
	}
	data, marshalErr := json.Marshal(labeledAgents)
	if marshalErr != nil {
		logging.Warningf("Saving labeled agents: %v", marshalErr)
		return
	}
	marshalErr = os.WriteFile(AgentsJSON, data, 0o600)
	if marshalErr != nil {
		logging.Warningf("Saving labeled agents: %v", marshalErr)
	}
}

// RefreshAgentLabel sets the label for an agent based on saved labels in JSON file.
func RefreshAgentLabel(a *def.Emp3r0rAgent) (label string) {
	data, err := os.ReadFile(AgentsJSON)
	if err != nil {
		logging.Warningf("Updating agent label: %v", err)
		return label
	}
	var labeledAgents []LabeledAgent
	err = json.Unmarshal(data, &labeledAgents)
	if err != nil {
		logging.Warningf("Invalid JSON: %v", err)
		return label
	}
	for _, labeled := range labeledAgents {
		if a.Tag == labeled.Tag {
			if val, ok := live.AgentControlMap.Load(a); ok {
				val.(*live.AgentControl).Label = labeled.Label
			}
			return labeled.Label
		}
	}
	return label
}

// SetAgentLabel sets a custom label for an agent by ID or tag.
// Returns error if agent not found or parameters invalid.
func SetAgentLabel(agentID, label string) error {
	if agentID == "" || label == "" {
		return fmt.Errorf("agent ID and label are required")
	}

	target := new(def.Emp3r0rAgent)

	// select by tag or index
	index, e := strconv.Atoi(agentID)
	if e != nil {
		// try by tag
		target = GetAgentByTag(agentID)
		if target == nil {
			return fmt.Errorf("cannot find agent by tag: %s", agentID)
		}
	} else {
		// try by index
		target = GetAgentByIndex(index)
	}

	// target exists?
	if target == nil {
		return fmt.Errorf("agent does not exist: %s", agentID)
	}

	if val, ok := live.AgentControlMap.Load(target); ok {
		val.(*live.AgentControl).Label = label // set label
	}
	PersistLabeledAgentsToFile()
	logging.Successf("%s has been labeled as %s", target.Tag, label)
	return nil
}
