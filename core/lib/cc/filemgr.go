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

func executeCmd(cmd string) {
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmd, err)
	}
}
