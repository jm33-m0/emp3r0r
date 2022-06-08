package cc

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// LsDir cache items in current directory
var LsDir []string

func FSSingleArgCmd(cmd string) {
	inputSlice := util.ParseCmd(cmd)
	cmdname := inputSlice[0]
	if len(inputSlice) < 2 {
		CliPrintError("%s requires one argument", cmdname)
		return
	}
	if cmdname == "kill" {
		inputSlice[0] = "#kill"
		cmd = strings.Join(inputSlice, " ")
	}

	// send cmd
	err := SendCmdToCurrentTarget(
		fmt.Sprintf("%s '%s'", inputSlice[0], inputSlice[1]),
		"")
	if err != nil {
		CliPrintError("%s failed: %v", cmdname, err)
		return
	}
}

func FSDoubleArgCmd(cmd string) {
	inputSlice := util.ParseCmd(cmd)
	cmdname := inputSlice[0]
	if len(inputSlice) < 3 {
		CliPrintError("%s requires two arguments", cmdname)
		return
	}

	// send cmd
	err := SendCmdToCurrentTarget(
		fmt.Sprintf("%s '%s' '%s'",
			inputSlice[0], inputSlice[1], inputSlice[2]),
		"")
	if err != nil {
		CliPrintError("%s failed: %v", cmdname, err)
		return
	}
}

func FSNoArgCmd(cmd string) {
	// send cmd
	if cmd == "ps" {
		cmd = "#ps"
	}
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmd, err)
		return
	}
}

func UploadToAgent(cmd string) {
	// target
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	inputSlice := util.ParseCmd(cmd)
	// #put file on agent
	if len(inputSlice) != 3 {
		CliPrintError("put <local path> <remote path>")
		return
	}

	if err = PutFile(inputSlice[1], inputSlice[2], target); err != nil {
		CliPrintError("Cannot put %s: %v", inputSlice[2], err)
	}
}

func DownloadFromAgent(cmd string) {
	// target
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	inputSlice := util.ParseCmd(cmd)
	if len(inputSlice) < 2 {
		CliPrintError("get <file path>")
		return
	} else {
		file_to_get := strings.Join(inputSlice[1:], " ")
		// #get file from agent
		go func() {
			if err = GetFile(file_to_get, target); err != nil {
				CliPrintError("Cannot get %s: %v", inputSlice[1], err)
			}
		}()
	}
}
