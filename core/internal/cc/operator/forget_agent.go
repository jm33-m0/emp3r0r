package operator

import (
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdForgetAgent removes an agent from the database
func CmdForgetAgent(cmd *cobra.Command, args []string) {
	uuid := strings.TrimSpace(args[0])
	if unquoted, err := strconv.Unquote(uuid); err == nil {
		uuid = unquoted
	}
	if byTag := agents.GetAgentByTag(uuid); byTag != nil && byTag.UUID != "" {
		uuid = byTag.UUID
	}

	// Create operation payload
	operation := def.Operation{
		AgentTag: uuid,
		Action:   "forget_agent",
	}

	// Send request to C2 server
	respBody, err := client.SendCBORRequest(transport.OperatorForgetAgent, operation)
	if err != nil {
		logging.Errorf("Failed to forget agent: %v", err)
		return
	}

	logging.Successf("%s", string(respBody))
	logging.Infof("Note: If the agent reconnects, it will be tracked again as a new entry")
}
