package operator

import (
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

func CmdLs(_ *cobra.Command, args []string) {
	dst := "."
	if len(args) != 0 {
		dst = args[0]
	}
	executeCmd(controllers.BuildLsCommand(dst))
}

func CmdPwd(_ *cobra.Command, _ []string) {
	executeCmd(controllers.BuildPwdCommand())
}

func CmdCd(_ *cobra.Command, args []string) {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Errorf("cd: no active target")
		return
	}

	dst := args[0]
	activeAgent.CWD = dst
	executeCmd(controllers.BuildCdCommand(dst))
}

func CmdCat(_ *cobra.Command, args []string) {
	dst := args[0]
	executeCmd(controllers.BuildCatCommand(dst))
}

func CmdCp(_ *cobra.Command, args []string) {
	src := args[0]
	dst := args[1]
	executeCmd(controllers.BuildCpCommand(src, dst))
}

func CmdRm(_ *cobra.Command, args []string) {
	dst := args[0]
	executeCmd(controllers.BuildRmCommand(dst))
}

func CmdMkdir(_ *cobra.Command, args []string) {
	dst := args[0]
	executeCmd(controllers.BuildMkdirCommand(dst))
}

func CmdMv(_ *cobra.Command, args []string) {
	src := args[0]
	dst := args[1]
	executeCmd(controllers.BuildMvCommand(src, dst))
}

func CmdPs(cmd *cobra.Command, args []string) {
	pid, _ := cmd.Flags().GetInt("pid")
	user, _ := cmd.Flags().GetString("user")
	name, _ := cmd.Flags().GetString("name")
	cmdLine, _ := cmd.Flags().GetString("cmdline")

	logging.Warningf("OPSEC: ps recorded as process/thread enumeration")
	executeCmd(controllers.BuildPsCommand(pid, user, name, cmdLine))
}

func CmdNetHelper(_ *cobra.Command, _ []string) {
	executeCmd(controllers.BuildNetHelperCommand())
}

func CmdSuicide(_ *cobra.Command, _ []string) {
	executeCmd(controllers.BuildSuicideCommand())
}

func CmdKill(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		logging.Errorf("kill: no PID specified")
		return
	}

	// Convert string PIDs to ints
	pids := make([]int, len(args))
	for i, pidStr := range args {
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 {
			logging.Errorf("kill: invalid PID '%s': must be a positive integer", pidStr)
			return
		}
		pids[i] = pid
	}

	// Build command using controller
	killCmd, err := controllers.BuildKillCommand(pids)
	if err != nil {
		logging.Errorf("kill: %v", err)
		return
	}

	executeCmd(killCmd)
}

func CmdResetLayout(_ *cobra.Command, _ []string) {
	err := cli.ResetPaneLayout()
	if err != nil {
		logging.Errorf("Failed to reset pane layout: %v", err)
	} else {
		logging.Infof("Pane layout reset to default proportions")
	}
}

// executeCmd is a thin wrapper that gets active agent and calls controller
func executeCmd(cmd string) {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Errorf("%s: no active target", cmd)
		return
	}

	err := controllers.ExecuteAgentCommand(activeAgent, cmd, client.SessionID)
	if err != nil {
		logging.Errorf("Failed to execute command: %v", err)
	}
}
