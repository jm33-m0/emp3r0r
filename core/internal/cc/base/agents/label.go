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
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		if rec.Label == "" {
			return true
		}
		labeled := LabeledAgent{
			Tag:   rec.Agent.Tag,
			Label: rec.Label,
		}
		for i, l := range old {
			if l.Tag == labeled.Tag {
				old[i].Label = labeled.Label // update label
				return true                  // already known from a previous run
			}
		}
		labeledAgents = append(labeledAgents, labeled)
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
	if marshalErr = os.WriteFile(AgentsJSON, data, 0o600); marshalErr != nil {
		logging.Warningf("Saving labeled agents: %v", marshalErr)
	}
}

// RefreshAgentLabel sets the label for an agent based on saved labels in JSON file.
func RefreshAgentLabel(a *def.Emp3r0rAgent) (label string) {
	if a == nil {
		return ""
	}
	data, err := os.ReadFile(AgentsJSON)
	if err != nil {
		logging.Warningf("Updating agent label: %v", err)
		return label
	}
	var labeledAgents []LabeledAgent
	if err = json.Unmarshal(data, &labeledAgents); err != nil {
		logging.Warningf("Invalid JSON: %v", err)
		return label
	}
	for _, labeled := range labeledAgents {
		if a.Tag != labeled.Tag {
			continue
		}
		// Records are immutable snapshots: copy, update, publish.
		if rec, ok := live.LookupAgent(a.UUID); ok {
			cp := *rec
			cp.Label = labeled.Label
			live.PublishAgent(&cp)
		}
		return labeled.Label
	}
	return label
}

// SetAgentLabel sets a custom label for an agent by ID or tag.
// Returns error if agent not found or parameters invalid.
func SetAgentLabel(agentID, label string) error {
	if agentID == "" || label == "" {
		return fmt.Errorf("agent ID and label are required")
	}

	var target *def.Emp3r0rAgent

	// select by tag or index
	index, e := strconv.Atoi(agentID)
	if e != nil {
		target = GetAgentByTag(agentID)
		if target == nil {
			return fmt.Errorf("cannot find agent by tag: %s", agentID)
		}
	} else {
		target = GetAgentByIndex(index)
	}

	if target == nil {
		return fmt.Errorf("agent does not exist: %s", agentID)
	}

	// Records are immutable snapshots: copy, update, publish.
	if rec, ok := live.LookupAgent(target.UUID); ok {
		cp := *rec
		cp.Label = label
		live.PublishAgent(&cp)
	}
	PersistLabeledAgentsToFile()
	logging.Successf("%s has been labeled as %s", target.Tag, label)
	return nil
}
