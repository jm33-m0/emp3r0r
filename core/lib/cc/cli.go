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
	// print banner
	err = CliBanner()
	if err != nil {
		CliFatalError("Banner: %v", err)
	} else {
		// start all services
		go TLSServer()
		go ShadowsocksServer()
		go InitModules()
	}

	// unlock incomplete downloads
	err = UnlockDownloads()
	if err != nil {
		CliPrintWarning("UnlockDownloads: %v", err)
	}

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
		line, readlineErr := EmpReadLine.Readline()
		if readlineErr == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if readlineErr == io.EOF {
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
			readlineErr = CmdHandler(line)
			if readlineErr != nil {
				color.Red(readlineErr.Error())
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

func cliPrintHelper(format string, a []interface{}, colorAttr color.Attribute, logPrefix string, alert bool) {
	msgColor := color.New(colorAttr)
	if logPrefix == "ERROR" || logPrefix == "ALERT" || logPrefix == "SUCCESS" {
		msgColor = color.New(colorAttr, color.Bold)
	}
	logMsg := msgColor.Sprintf(format, a...)
	log.Print(logMsg)

	// Save log to file
	logFile, logOpenErr := os.OpenFile("emp3r0r.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if logOpenErr != nil {
		log.Printf("cliPrintHelper: %v", logOpenErr)
		return
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)
	logger.Print(logMsg)

	if IsAPIEnabled {
		var resp APIResponse
		msg := GetDateTime() + " " + logPrefix + ": " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = alert
		resp.MsgType = LOG
		data, jsonMarshalErr := json.Marshal(resp)
		if jsonMarshalErr != nil {
			log.Printf("cliPrintHelper: %v", jsonMarshalErr)
			return
		}
		_, jsonMarshalErr = APIConn.Write([]byte(data))
		if jsonMarshalErr != nil {
			log.Printf("cliPrintHelper: %v", jsonMarshalErr)
		}
	}
}

func CliPrintDebug(format string, a ...interface{}) {
	if DebugLevel >= 3 {
		cliPrintHelper(format, a, color.FgBlue, "DEBUG", false)
	}
}

func CliPrintInfo(format string, a ...interface{}) {
	if DebugLevel >= 2 {
		cliPrintHelper(format, a, color.FgHiBlue, "INFO", false)
	}
}

func CliPrintWarning(format string, a ...interface{}) {
	if DebugLevel >= 1 {
		cliPrintHelper(format, a, color.FgHiYellow, "WARN", false)
	}
}

func CliPrint(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.FgCyan, "PRINT", false)
}

func CliMsg(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.FgCyan, "MSG", false)
}

func CliAlert(textColor color.Attribute, format string, a ...interface{}) {
	cliPrintHelper(format, a, textColor, "ALERT", false)
}

func CliPrintSuccess(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.FgHiGreen, "SUCCESS", true)
}

func CliFatalError(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.FgHiRed, "ERROR", true)
	CliMsg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	log.Fatal(color.New(color.Bold, color.FgHiRed).Sprintf(format, a...))
}

func CliPrintError(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.FgHiRed, "ERROR", true)
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

	for {
		answer, readlineErr := EmpReadLine.Readline()
		if readlineErr != nil {
			if readlineErr == readline.ErrInterrupt || readlineErr == io.EOF {
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

	answer, readlineErr := EmpReadLine.Readline()
	if readlineErr != nil {
		if readlineErr == readline.ErrInterrupt || readlineErr == io.EOF {
			return false
		}
		color.Red(readlineErr.Error())
	}

	answer = strings.ToLower(answer)
	return answer == "y"
}

// CliListOptions list currently available options for `set`
func CliListOptions() {
	if CurrentMod == "none" {
		CliPrintWarning("No module selected")
		return
	}
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	opts := make(map[string]string)

	opts["module"] = CurrentMod
	if CurrentTarget != nil {
		_, exist := Targets[CurrentTarget]
		if exist {
			shortName := strings.Split(CurrentTarget.Tag, "-agent")[0]
			opts["target"] = shortName
		} else {
			opts["target"] = "<blank>"
		}
	} else {
		opts["target"] = "<blank>"
	}

	for k, v := range Options {
		if v != nil {
			opts[k] = v.Val
		}
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
			[]string{
				util.SplitLongLine(k, 20),
				util.SplitLongLine(help, 20),
				util.SplitLongLine(v, 20),
			})
	}
	table.AppendBulk(tdata)
	table.Render()
	out := tableString.String()
	AdaptiveTable(out)
	CliPrint("\n%s", out)
}

// CliListCmds list all commands in tree format
func CliListCmds(w io.Writer) {
	_, ioErr := io.WriteString(w, "Commands:\n")
	if ioErr != nil {
		return
	}
	_, ioErr = io.WriteString(w, CliCompleter.Tree("    "))
	if ioErr != nil {
		return
	}
}

// CliBanner prints banner
func CliBanner() error {
	data, encodingErr := base64.StdEncoding.DecodeString(cliBannerB64)
	if encodingErr != nil {
		return errors.New("failed to print banner: " + encodingErr.Error())
	}

	// print banner line by line
	banner := strings.Split(string(data), "\n")
	for _, line := range banner {
		color.Cyan(line)
		util.TakeABlink()
	}
	cow, encodingErr := cowsay.New(
		cowsay.BallonWidth(100),
		cowsay.Random(),
	)
	if encodingErr != nil {
		log.Fatalf("CowSay: %v", encodingErr)
	}

	// C2 names
	encodingErr = LoadCACrt()
	if encodingErr != nil {
		CliPrintWarning("Failed to parse CA cert: %v", encodingErr)
	}
	c2_names := tun.NamesInCert(ServerCrtFile)
	if len(c2_names) <= 0 {
		CliFatalError("C2 has no names?")
	}
	name_list := strings.Join(c2_names, ", ")

	say, encodingErr := cow.Say(fmt.Sprintf("welcome! you are using version %s,\n"+
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
	if encodingErr != nil {
		log.Fatalf("CowSay: %v", encodingErr)
	}
	color.Cyan("%s\n\n", say)
	util.TakeABlink()
	return nil
}

// CliPrettyPrint prints two-column help info
func CliPrettyPrint(header1, header2 string, map2write *map[string]string) {
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg, marshalErr := json.Marshal(map2write)
		if marshalErr != nil {
			log.Printf("CliPrettyPrint: %v", marshalErr)
		}
		resp.MsgData = msg
		resp.Alert = false
		resp.MsgType = JSON
		data, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			log.Printf("CliPrettyPrint: %v", marshalErr)
		}
		_, marshalErr = APIConn.Write([]byte(data))
		if marshalErr != nil {
			log.Printf("CliPrettyPrint: %v", marshalErr)
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
	stdin, stdinErr := cmd.StdinPipe()
	if stdinErr != nil {
		CliPrintWarning("CopyToClipboard read stdin: %v", stdinErr)
		return
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(data)
	}()

	stdinErr = cmd.Run()
	if stdinErr != nil {
		CliPrintWarning("CopyToClipboard: %v", stdinErr)
	}
	CliPrintInfo("Copied to clipboard")
}
