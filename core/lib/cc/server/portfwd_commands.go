package server

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/agents"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/network"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// DeletePortFwdSession deletes a port mapping session by ID.
func DeletePortFwdSession(cmd *cobra.Command, args []string) {
	sessionID, err := cmd.Flags().GetString("id")
	if err != nil {
		logging.Errorf("DeletePortFwdSession: %v", err)
		return
	}
	if sessionID == "" {
		logging.Errorf("DeletePortFwdSession: no session ID provided")
		return
	}
	network.PortFwdsMutex.Lock()
	defer network.PortFwdsMutex.Unlock()
	for id, session := range network.PortFwds {
		if id == sessionID {
			err := agents.SendCmd(fmt.Sprintf("%s --id %s", emp3r0r_def.C2CmdDeletePortFwd, id), "", session.Agent)
			if err != nil {
				logging.Warningf("Tell agent %s to delete port mapping %s: %v", session.Agent.Tag, sessionID, err)
			}
			session.Cancel()
			delete(network.PortFwds, id)
		}
	}
}

// ListPortFwds lists currently active port mappings.
func ListPortFwds(cmd *cobra.Command, args []string) {
	tdata := [][]string{}
	for id, portmap := range network.PortFwds {
		if portmap.Sh == nil {
			portmap.Cancel()
			continue
		}
		to := portmap.To + " (Agent) "
		lport := portmap.Lport + " (CC) "
		if portmap.Reverse {
			to = portmap.To + " (CC) "
			lport = portmap.Lport + " (Agent) "
		}
		tdata = append(tdata,
			[]string{
				lport,
				to,
				util.SplitLongLine(portmap.Agent.Tag, 10),
				util.SplitLongLine(portmap.Description, 10),
				util.SplitLongLine(id, 10),
			})
	}
	header := []string{"Local Port", "To", "Agent", "Description", "ID"}
	tableStr := cli.BuildTable(header, tdata)
	cli.AdaptiveTable(tableStr)
	logging.Infof("\n\033[0m%s\n\n", tableStr)
}
