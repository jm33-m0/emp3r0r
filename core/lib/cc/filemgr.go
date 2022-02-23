package cc

import (
	"strings"
)

// LsDir cache items in current directory
var LsDir []string

func SingleArgCmd(cmd string) {
	inputSlice := strings.Fields(cmd)
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
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmdname, err)
		return
	}
}

func DoubleArgCmd(cmd string) {
	inputSlice := strings.Fields(cmd)
	cmdname := inputSlice[0]
	if len(inputSlice) < 3 {
		CliPrintError("%s requires two arguments", cmdname)
		return
	}

	// send cmd
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("%s failed: %v", cmdname, err)
		return
	}
}

func NoArgCmd(cmd string) {
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

	inputSlice := strings.Fields(cmd)
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

	inputSlice := strings.Fields(cmd)
	// #get file from agent
	if len(inputSlice) != 2 {
		CliPrintError("get <remote path>")
		return
	} else {
		go func() {
			if err = GetFile(inputSlice[1], target); err != nil {
				CliPrintError("Cannot get %s: %v", inputSlice[1], err)
			}
		}()
	}
}
