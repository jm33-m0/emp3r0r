//go:build linux
// +build linux

package cc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	cowsay "github.com/Code-Hex/Neo-cowsay/v2"
	"github.com/bettercap/readline"
	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/ss"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

const (
	PromptName = "emp3r0r"
	ClearTerm  = "\033[2J"
)

var (
	// CliCompleter holds all command completions
	CliCompleter = readline.NewPrefixCompleter()

	// CmdCompls completions for readline
	CmdCompls []readline.PrefixCompleterInterface

	// InitCmdCompls initial completions for readline, so we can roll back
	InitCmdCompls []readline.PrefixCompleterInterface

	// EmpReadLine : our commandline
	EmpReadLine *readline.Instance

	// EmpPrompt : the prompt string
	EmpPrompt = color.HiCyanString(PromptName + " > ")

	err error
)

// CliMain launches the commandline UI
func CliMain() {
	// completer
	CmdCompls = []readline.PrefixCompleterInterface{
		readline.PcItem("set",
			readline.PcItemDynamic(listOptions(),
				readline.PcItemDynamic(listValChoices()))),

		readline.PcItem("use",
			readline.PcItemDynamic(listMods())),

		readline.PcItem("rm",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("mv",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("mkdir",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("ls",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("cp",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("cd",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("get",
			readline.PcItemDynamic(listRemoteDir())),

		readline.PcItem("put",
			readline.PcItemDynamic(listLocalFiles("./"))),

		readline.PcItem(HELP,
			readline.PcItemDynamic(listMods())),

		readline.PcItem("target",
			readline.PcItemDynamic(listTargetIndexTags())),

		readline.PcItem("label",
			readline.PcItemDynamic(listTargetIndexTags())),

		readline.PcItem("delete_port_fwd",
			readline.PcItemDynamic(listPortMappings())),
	}

	for cmd := range CommandHelp {
		if cmd == "set" ||
			cmd == "use" ||
			cmd == "get" ||
			cmd == "put" ||
			cmd == "cp" ||
			cmd == "mkdir" ||
			cmd == "target" ||
			cmd == "label" ||
			cmd == "delete_port_fwd" ||
			cmd == "rm" ||
			cmd == "mv" ||
			cmd == "ls" ||
			cmd == "cd" ||
			cmd == HELP {
			continue
		}
		CmdCompls = append(CmdCompls, readline.PcItem(cmd))
	}
	CliCompleter.SetChildren(CmdCompls)
	// remember initial CmdCompls
	InitCmdCompls = CmdCompls

	// prompt setup
	filterInput := func(r rune) (rune, bool) {
		switch r {
		// block CtrlZ feature
		case readline.CharCtrlZ:
			return r, false
		}
		return r, true
	}

	// set up readline instance
	EmpReadLine, err = readline.NewEx(&readline.Config{
		Prompt:          EmpPrompt,
		HistoryFile:     "./.emp3r0r.history",
		AutoComplete:    CliCompleter,
		InterruptPrompt: "^C\nExiting...\n",
		EOFPrompt:       "^D\nExiting...\n",

		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})
	if err != nil {
		panic(err)
	}
	defer EmpReadLine.Close()
	log.SetOutput(EmpReadLine.Stderr())

	err = TmuxInitWindows()
	if err != nil {
		log.Fatalf("Fatal TMUX error: %v, please run `tmux kill-server` and re-run emp3r0r", err)
	}

	defer TmuxDeinitWindows()

start:
	SetDynamicPrompt()
	for {
		line, err := EmpReadLine.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		// readline-related commands
		switch line {
		case "commands":
			CliListCmds(EmpReadLine.Stderr())
		case "exit":
			return
		case "quit":
			return
		case "q":
			return

		// process other commands
		default:
			err = CmdHandler(line)
			if err != nil {
				color.Red(err.Error())
			}
		}
		fmt.Printf("\n")
	}

	// ask the user if they really want to leave
	if CliYesNo("Are you sure you want to leave") {
		// os.Exit(0)
		return
	}

	fmt.Printf("\n")
	goto start
}

// SetDynamicPrompt set prompt with module and target info
func SetDynamicPrompt() {
	shortName := "local" // if no target is selected
	if CurrentTarget != nil && IsAgentExist(CurrentTarget) {
		shortName = strings.Split(CurrentTarget.Tag, "-agent")[0]
	}
	if CurrentMod == "<blank>" {
		CurrentMod = "none" // if no module is selected
	}
	dynamicPrompt := fmt.Sprintf("%s @%s (%s) "+
		color.New(color.Bold, color.FgHiCyan).Sprintf("> "),
		color.New(color.Bold, color.FgHiCyan).Sprint(PromptName),
		color.New(color.FgCyan, color.Underline).Sprint(shortName),
		color.New(color.FgHiBlue).Sprint(CurrentMod),
	)
	EmpReadLine.Config.Prompt = dynamicPrompt
	EmpReadLine.SetPrompt(dynamicPrompt)
}

// CliPrintDebug print log in blue
func CliPrintDebug(format string, a ...interface{}) {
	if DebugLevel >= 3 {
		log.Println(color.BlueString(format, a...))
		if IsAPIEnabled {
			// send to socket
			var resp APIResponse
			msg := GetDateTime() + " DEBUG: " + fmt.Sprintf(format, a...)
			resp.MsgData = []byte(msg)
			resp.Alert = false
			resp.MsgType = LOG
			data, err := json.Marshal(resp)
			if err != nil {
				log.Printf("CliPrintDebug: %v", err)
				return
			}
			_, err = APIConn.Write([]byte(data))
			if err != nil {
				log.Printf("CliPrintDebug: %v", err)
			}
		}
	}
}

// CliPrintInfo print log in hiblue
func CliPrintInfo(format string, a ...interface{}) {
	if DebugLevel >= 2 {
		log.Println(color.HiBlueString(format, a...))
		if IsAPIEnabled {
			// send to socket
			var resp APIResponse
			msg := GetDateTime() + " INFO: " + fmt.Sprintf(format, a...)
			resp.MsgData = []byte(msg)
			resp.Alert = false
			resp.MsgType = LOG
			data, err := json.Marshal(resp)
			if err != nil {
				log.Printf("CliPrintInfo: %v", err)
				return
			}
			_, err = APIConn.Write([]byte(data))
			if err != nil {
				log.Printf("CliPrintInfo: %v", err)
			}
		}
	}
}

// CliPrintWarning print log in hiyellow
func CliPrintWarning(format string, a ...interface{}) {
	if DebugLevel >= 1 {
		log.Println(color.HiYellowString(format, a...))
		if IsAPIEnabled {
			// send to socket
			var resp APIResponse
			msg := GetDateTime() + " WARN: " + fmt.Sprintf(format, a...)
			resp.MsgData = []byte(msg)
			resp.Alert = false
			resp.MsgType = LOG
			data, err := json.Marshal(resp)
			if err != nil {
				log.Printf("CliPrintWarning: %v", err)
				return
			}
			_, err = APIConn.Write([]byte(data))
			if err != nil {
				log.Printf("CliPrintWarning: %v", err)
			}
		}
	}
}

// CliPrint print in bold cyan without logging prefix, regardless of debug level
func CliPrint(format string, a ...interface{}) {
	msg_color := color.New(color.Bold, color.FgCyan)
	fmt.Println(msg_color.Sprintf(format, a...))
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg := GetDateTime() + " PRINT: " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = false
		resp.MsgType = LOG
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliPrint: %v", err)
			return
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliPrint: %v", err)
		}
	}
}

// CliMsg print log in bold cyan, regardless of debug level
func CliMsg(format string, a ...interface{}) {
	msg_color := color.New(color.Bold, color.FgCyan)
	log.Println(msg_color.Sprintf(format, a...))
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg := GetDateTime() + " MSG: " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = false
		resp.MsgType = LOG
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliMsg: %v", err)
			return
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliMsg: %v", err)
		}
	}
}

// CliAlert print log in blinking text
func CliAlert(textColor color.Attribute, format string, a ...interface{}) {
	alertColor := color.New(color.Bold, textColor, color.BlinkSlow)
	log.Print(alertColor.Sprintf(format, a...))
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg := GetDateTime() + " ALERT: " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = false
		resp.MsgType = LOG
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliAlert: %v", err)
			return
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliAlert: %v", err)
		}
	}
}

// CliPrintSuccess print log in green
func CliPrintSuccess(format string, a ...interface{}) {
	successColor := color.New(color.Bold, color.FgHiGreen)
	log.Print(successColor.Sprintf(format, a...))
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg := GetDateTime() + " SUCCESS: " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = true
		resp.MsgType = LOG
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliPrintSuccess: %v", err)
			return
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliPrintSuccess: %v", err)
		}
	}
}

// CliFatalError print log in red, and exit
func CliFatalError(format string, a ...interface{}) {
	errorColor := color.New(color.Bold, color.FgHiRed)
	CliMsg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	log.Fatal(errorColor.Sprintf(format, a...))
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg := GetDateTime() + " ERROR: " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = true
		resp.MsgType = LOG
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliPrintError: %v", err)
			return
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliPrintError: %v", err)
		}
	}
}

// CliPrintError print log in red
func CliPrintError(format string, a ...interface{}) {
	errorColor := color.New(color.Bold, color.FgHiRed)
	log.Print(errorColor.Sprintf(format, a...))
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg := GetDateTime() + " ERROR: " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = true
		resp.MsgType = LOG
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliPrintError: %v", err)
			return
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliPrintError: %v", err)
		}
	}
}

// CliAsk prompt for an answer from user
func CliAsk(prompt string, allow_empty bool) (answer string) {
	// if there's no way to show prompt
	if IsAPIEnabled {
		return "No terminal available"
	}

	EmpReadLine.SetPrompt(color.HiMagentaString(prompt))
	EmpReadLine.Config.EOFPrompt = ""
	EmpReadLine.Config.InterruptPrompt = ""

	defer SetDynamicPrompt()

	var err error
	for {
		answer, err = EmpReadLine.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				break
			}
		}
		answer = strings.TrimSpace(answer)
		if answer != "" && !allow_empty {
			break
		}
	}

	return
}

// CliYesNo prompt for a y/n answer from user
func CliYesNo(prompt string) bool {
	// always return true if there's no way to show prompt
	if IsAPIEnabled {
		return true
	}

	EmpReadLine.SetPrompt(color.HiMagentaString(prompt + "? [y/N] "))
	EmpReadLine.Config.EOFPrompt = ""
	EmpReadLine.Config.InterruptPrompt = ""

	defer SetDynamicPrompt()

	answer, err := EmpReadLine.Readline()
	if err != nil {
		if err == readline.ErrInterrupt || err == io.EOF {
			return false
		}
		color.Red(err.Error())
	}

	answer = strings.ToLower(answer)
	return answer == "y"
}

// CliListOptions list currently available options for `set`
func CliListOptions() {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	opts := make(map[string]string)
	opts["module"] = CurrentMod
	_, exist := Targets[CurrentTarget]
	if exist {
		shortName := strings.Split(CurrentTarget.Tag, "-agent")[0]
		opts["target"] = shortName
	} else {
		opts["target"] = "<blank>"
	}

	for k, v := range Options {
		opts[k] = v.Val
	}

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Option", "Help", "Value"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetColWidth(20)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})
	table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor})

	// fill table
	module_help, is_help_exist := emp3r0r_data.ModuleHelp[CurrentMod]
	for k, v := range opts {
		help := "N/A"
		if k == "module" {
			help = "Selected module"
		}
		if k == "target" {
			help = "Selected target"
		}
		if is_help_exist {
			h, ok := module_help[k]
			if ok {
				help = h
			}
		}

		tdata = append(tdata,
			[]string{util.SplitLongLine(k, 20),
				util.SplitLongLine(help, 20),
				util.SplitLongLine(v, 20)})
	}
	table.AppendBulk(tdata)
	table.Render()
	out := tableString.String()
	AdaptiveTable(out)
	CliPrint("\n%s", out)
}

// CliListCmds list all commands in tree format
func CliListCmds(w io.Writer) {
	_, err := io.WriteString(w, "Commands:\n")
	if err != nil {
		return
	}
	_, err = io.WriteString(w, CliCompleter.Tree("    "))
	if err != nil {
		return
	}
}

// CliBanner prints banner
func CliBanner() error {
	data, err := base64.StdEncoding.DecodeString(cliBannerB64)
	if err != nil {
		return errors.New("Failed to print banner: " + err.Error())
	}

	color.Cyan(string(data))
	cow, err := cowsay.New(
		cowsay.BallonWidth(40),
		cowsay.Random(),
	)
	if err != nil {
		log.Fatalf("CowSay: %v", err)
	}

	// C2 names
	err = LoadCACrt()
	if err != nil {
		CliPrintWarning("Failed to parse CA cert: %v", err)
	}
	c2_names := tun.NamesInCert(ServerCrtFile)
	if len(c2_names) <= 0 {
		CliFatalError("C2 has no names?")
	}
	name_list := strings.Join(c2_names, ", ")

	say, err := cow.Say(fmt.Sprintf("welcome! you are using version %s,\n"+
		"C2 listening on *:%s,\n"+
		"Shadowsocks port *:%s,\n"+
		"KCP port *:%s,\n"+
		"C2 names: %s\n"+
		"CA fingerprint: %s",
		emp3r0r_data.Version,
		RuntimeConfig.CCPort,
		RuntimeConfig.ShadowsocksPort,
		RuntimeConfig.KCPPort,
		name_list,
		RuntimeConfig.CAFingerprint))
	if err != nil {
		log.Fatalf("CowSay: %v", err)
	}
	color.Cyan("%s\n\n", say)
	return nil
}

// CliPrettyPrint prints two-column help info
func CliPrettyPrint(header1, header2 string, map2write *map[string]string) {
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg, err := json.Marshal(map2write)
		if err != nil {
			log.Printf("CliPrettyPrint: %v", err)
		}
		resp.MsgData = msg
		resp.Alert = false
		resp.MsgType = JSON
		data, err := json.Marshal(resp)
		if err != nil {
			log.Printf("CliPrettyPrint: %v", err)
		}
		_, err = APIConn.Write([]byte(data))
		if err != nil {
			log.Printf("CliPrettyPrint: %v", err)
		}
	}

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{header1, header2})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetColWidth(20)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor})

	// fill table
	for c1, c2 := range *map2write {
		tdata = append(tdata,
			[]string{util.SplitLongLine(c1, 20), util.SplitLongLine(c2, 20)})
	}
	table.AppendBulk(tdata)
	table.Render()
	out := tableString.String()
	AdaptiveTable(out)
	CliPrint("\n%s", out)
}

// encoded logo of emp3r0r
const cliBannerB64 string = `
CuKWkeKWkeKWkeKWkeKWkeKWkeKWkSDilpHilpHilpEgICAg4paR4paR4paRIOKWkeKWkeKWkeKW
keKWkeKWkSAg4paR4paR4paR4paR4paR4paRICDilpHilpHilpHilpHilpHilpEgICDilpHilpHi
lpHilpHilpHilpEgIOKWkeKWkeKWkeKWkeKWkeKWkQrilpLilpIgICAgICDilpLilpLilpLilpIg
IOKWkuKWkuKWkuKWkiDilpLilpIgICDilpLilpIgICAgICDilpLilpIg4paS4paSICAg4paS4paS
IOKWkuKWkiAg4paS4paS4paS4paSIOKWkuKWkiAgIOKWkuKWkgrilpLilpLilpLilpLilpIgICDi
lpLilpIg4paS4paS4paS4paSIOKWkuKWkiDilpLilpLilpLilpLilpLilpIgICDilpLilpLilpLi
lpLilpIgIOKWkuKWkuKWkuKWkuKWkuKWkiAg4paS4paSIOKWkuKWkiDilpLilpIg4paS4paS4paS
4paS4paS4paSCuKWk+KWkyAgICAgIOKWk+KWkyAg4paT4paTICDilpPilpMg4paT4paTICAgICAg
ICAgICDilpPilpMg4paT4paTICAg4paT4paTIOKWk+KWk+KWk+KWkyAg4paT4paTIOKWk+KWkyAg
IOKWk+KWkwrilojilojilojilojilojilojilogg4paI4paIICAgICAg4paI4paIIOKWiOKWiCAg
ICAgIOKWiOKWiOKWiOKWiOKWiOKWiCAg4paI4paIICAg4paI4paIICDilojilojilojilojiloji
loggIOKWiOKWiCAgIOKWiOKWiAoKCmEgbGludXggcG9zdC1leHBsb2l0YXRpb24gZnJhbWV3b3Jr
IG1hZGUgYnkgbGludXggdXNlcgoKaHR0cHM6Ly9naXRodWIuY29tL2ptMzMtbTAvZW1wM3IwcgoK
Cg==
`

// autocomplete module options
func listValChoices() func(string) []string {
	return func(line string) []string {
		ret := make([]string, 0)
		for _, opt := range Options {
			ret = append(ret, opt.Vals...)
		}
		return ret
	}
}

// autocomplete modules names
func listMods() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		for mod := range ModuleHelpers {
			names = append(names, mod)
		}
		return names
	}
}

// autocomplete portfwd session IDs
func listPortMappings() func(string) []string {
	return func(line string) []string {
		ids := make([]string, 0)
		for id := range PortFwds {
			ids = append(ids, id)
		}
		return ids
	}
}

// autocomplete target index and tags
func listTargetIndexTags() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		for t, c := range Targets {
			idx := c.Index
			tag := t.Tag
			names = append(names, strconv.Itoa(idx))
			names = append(names, tag)
		}
		return names
	}
}

// autocomplete option names
func listOptions() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)

		for opt := range Options {
			names = append(names, opt)
		}
		return names
	}
}

// remote autocomplete items in $PATH
func listAgentExes(agent *emp3r0r_data.AgentSystemInfo) []string {
	CliPrintDebug("listing exes in PATH")
	exes := make([]string, 0)
	if agent == nil {
		CliPrintDebug("No valid target selected so no autocompletion for exes")
		return exes
	}
	for _, exe := range agent.Exes {
		exe = strings.ReplaceAll(exe, "\t", "\\t")
		exe = strings.ReplaceAll(exe, " ", "\\ ")
		exes = append(exes, exe)
	}
	CliPrintDebug("Exes found on agent '%s':\n%v",
		agent.Tag, exes)
	return exes
}

// when a target is selected, update CmdCompls with PATH items
func updateAgentExes(agent *emp3r0r_data.AgentSystemInfo) {
	exes := listAgentExes(agent)
	temp_CmdCompls := InitCmdCompls

	for _, exe := range exes {
		temp_CmdCompls = append(temp_CmdCompls, readline.PcItem(exe))
	}

	CmdCompls = temp_CmdCompls
	CliCompleter.SetChildren(CmdCompls)
}

// remote ls autocomplete items in current directory
func listRemoteDir() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		for _, name := range LsDir {
			name = strings.ReplaceAll(name, "\t", "\\t")
			name = strings.ReplaceAll(name, " ", "\\ ")
			names = append(names, name)
		}
		return names
	}
}

// Function constructor - constructs new function for listing given directory
// local ls
func listLocalFiles(path string) func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		files, _ := os.ReadDir(path)
		for _, f := range files {
			name := strings.ReplaceAll(f.Name(), "\t", "\\t")
			name = strings.ReplaceAll(name, " ", "\\ ")
			names = append(names, name)
		}
		return names
	}
}

// automatically resize CommandPane according to table width
func AdaptiveTable(tableString string) {
	TmuxUpdatePanes()
	row_len := len(strings.Split(tableString, "\n")[0])
	if CommandPane.Width < row_len {
		CliPrintDebug("Command Pane %d vs %d table width, resizing", CommandPane.Width, row_len)
		CommandPane.ResizePane("x", row_len)
	}
}

func setDebugLevel(cmd string) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) != 2 {
		CliPrintError("debug <0, 1, 2, 3>")
		return
	}
	level, e := strconv.Atoi(cmdSplit[1])
	if e != nil {
		CliPrintError("Invalid debug level: %v", err)
		return
	}
	DebugLevel = level
	if DebugLevel > 2 {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lmsgprefix)
		ss.ServerConfig.Verbose = true
	} else {
		log.SetFlags(log.Ldate | log.Ltime | log.LstdFlags)
	}
}

// CopyToClipboard copy data to clipboard using xsel -b
func CopyToClipboard(data []byte) {
	exe := "xsel"
	cmd := exec.Command("xsel", "-bi")
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		exe = "wl-copy"
		cmd = exec.Command("wl-copy")
	} else if os.Getenv("DISPLAY") == "" {
		CliPrintWarning("Neither Wayland nor X11 is running, CopyToClipboard will abort")
		return
	}
	if !util.IsCommandExist(exe) {
		CliPrintWarning("%s not installed", exe)
		return
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		CliPrintWarning("CopyToClipboard read stdin: %v", err)
		return
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(data)
	}()

	err = cmd.Run()
	if err != nil {
		CliPrintWarning("CopyToClipboard: %v", err)
	}
	CliPrintInfo("Copied to clipboard")
}
