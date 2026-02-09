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
		if readErr != nil {
			logging.Warningf("Reading labeled agents: %v", readErr)
		}
		readErr = json.Unmarshal(data, &old)
		if readErr != nil {
			logging.Warningf("Reading labeled agents: %v", readErr)
		}
	}
outter:
	for t, c := range live.AgentControlMap {
		if c.Label == "" {
			continue
		}
		labeled := &LabeledAgent{
			Tag:   t.Tag,
			Label: c.Label,
		}
		for i, l := range old {
			if l.Tag == labeled.Tag {
				old[i].Label = labeled.Label // update label
				old[i] = l
				continue outter
			}
		}
		labeledAgents = append(labeledAgents, *labeled)
	}
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
		return
	}
	var labeledAgents []LabeledAgent
	err = json.Unmarshal(data, &labeledAgents)
	if err != nil {
		logging.Warningf("Invalid JSON: %v", err)
		return
	}
	for _, labeled := range labeledAgents {
		if a.Tag == labeled.Tag {
			if live.AgentControlMap[a] != nil {
				live.AgentControlMap[a].Label = labeled.Label
			}
			return labeled.Label
		}
	}
	return
}

// SetAgentLabel sets a custom label for an agent by ID or tag.
// Returns error if agent not found or parameters invalid.
func SetAgentLabel(agentID string, label string) error {
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

	live.AgentControlMap[target].Label = label // set label
	PersistLabeledAgentsToFile()
	logging.Successf("%s has been labeled as %s", target.Tag, label)
	return nil
}
