package operator

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdForgetAgent removes an agent from the database
func CmdForgetAgent(cmd *cobra.Command, args []string) {
	uuid := args[0]

	// Create operation payload
	operation := def.Operation{
		AgentTag: uuid,
		Action:   "forget_agent",
	}

	// Send request to C2 server
	url := fmt.Sprintf("%s/%s", OperatorRootURL, transport.OperatorForgetAgent)
	respBody, err := sendCBORRequest(url, operation)
	if err != nil {
		logging.Errorf("Failed to forget agent: %v", err)
		return
	}

	logging.Successf("%s", string(respBody))
	logging.Infof("Note: If the agent reconnects, it will be tracked again as a new entry")
}
