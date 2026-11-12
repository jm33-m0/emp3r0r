package operator

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdForgetAgent removes an agent from the database
func CmdForgetAgent(_ *cobra.Command, args []string) {
	body, err := ForgetAgent(args[0])
	if err != nil {
		logging.Errorf("Failed to forget agent: %v", err)
		return
	}
	logging.Successf("%s", body)
	logging.Infof("Note: If the agent reconnects, it will be tracked again as a new entry")
}
