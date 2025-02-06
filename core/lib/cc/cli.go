//go:build linux
// +build linux

package cc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	cowsay "github.com/Code-Hex/Neo-cowsay/v2"
	"github.com/alecthomas/chroma/quick"
	"github.com/fatih/color"
	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/ss"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
	"github.com/reeflective/console"
	"github.com/spf13/cobra"
)

const (
	AppName = "emp3r0r"
)

var (
	// Store agents' output
	CommandOuputLogs = ""

	// Emp3r0rConsole: the main console interface
	Emp3r0rConsole = console.New(AppName)

	// EmpPrompt : the prompt string
	EmpPrompt = color.HiCyanString(AppName + " > ")

	err error
)

// CliMain launches the commandline UI
func CliMain() {
	// start all services
	go TLSServer()
	go ShadowsocksServer()
	go InitModules()

	// unlock incomplete downloads
	err = UnlockDownloads()
	if err != nil {
		CliPrintDebug("UnlockDownloads: %v", err)
	}
	mainMenu := Emp3r0rConsole.NewMenu("")
	Emp3r0rConsole.SetPrintLogo(CliBanner)

	// History
	histFile := fmt.Sprintf("%s/%s.history", AppName, EmpWorkSpace)
	mainMenu.AddHistorySourceFile(AppName, histFile)

	// Commands
	mainMenu.SetCommands(Emp3r0rCommands(Emp3r0rConsole))

	// Interrupts
	mainMenu.AddInterrupt(io.EOF, exitEmp3r0r)

	// prompt
	prompt := mainMenu.Prompt()
	prompt.Primary = SetDynamicPrompt
	prompt.Secondary = func() string { return ">" }
	prompt.Right = func() string { return fmt.Sprint(time.Now().Format("03:04:05")) }
	prompt.Transient = func() string { return ">>>" }

	// Syntax highlighting
	Emp3r0rConsole.Shell().SyntaxHighlighter = highLighter

	// Tmux setup
	err = TmuxInitWindows()
	if err != nil {
		log.Fatalf("Fatal TMUX error: %v, please run `tmux kill-session -t emp3r0r` and re-run emp3r0r", err)
	}
	defer TmuxDeinitWindows()

	// Run the console
	Emp3r0rConsole.Start()
}

func highLighter(line []rune) string {
	var highlightedStr strings.Builder
	err := quick.Highlight(&highlightedStr, string(line), "shell", "terminal256", "monokai")
	if err != nil {
		return string(line)
	}

	return highlightedStr.String()
}

// SetDynamicPrompt set prompt with module and target info
func SetDynamicPrompt() string {
	shortName := "local" // if no target is selected
	prompt_arrow := color.New(color.Bold, color.FgHiCyan).Sprintf("\n$ ")
	prompt_name := color.New(color.Bold, color.FgBlack, color.BgHiWhite).Sprint(AppName)
	transport := color.New(color.FgRed).Sprint("local")

	if CurrentTarget != nil && IsAgentExist(CurrentTarget) {
		shortName = strings.Split(CurrentTarget.Tag, "-agent")[0]
		if CurrentTarget.HasRoot {
			prompt_arrow = color.New(color.Bold, color.FgHiGreen).Sprint("\n# ")
			prompt_name = color.New(color.Bold, color.FgBlack, color.BgHiGreen).Sprint(AppName)
		}
		transport = getTransportString(CurrentTarget.Transport)
	}
	if CurrentMod == "<blank>" {
		CurrentMod = "none" // if no module is selected
	}
	agent_name := color.New(color.FgCyan, color.Underline).Sprint(shortName)
	mod_name := color.New(color.FgHiBlue).Sprint(CurrentMod)

	dynamicPrompt := fmt.Sprintf("\n%s - %s @%s (%s) "+prompt_arrow,
		prompt_name,
		transport,
		agent_name,
		mod_name,
	)
	return dynamicPrompt
}

func getTransportString(transportStr string) string {
	transportStr = strings.ToLower(transportStr)
	switch {
	case strings.Contains(transportStr, "http2"):
		return color.New(color.FgHiBlue).Sprint("http2")
	case strings.Contains(transportStr, "shadowsocks"):
		if strings.Contains(transportStr, "kcp") {
			return color.New(color.FgHiMagenta).Sprint("kcp")
		}
		return color.New(color.FgHiMagenta).Sprint("ss")
	case strings.Contains(transportStr, "tor"):
		return color.New(color.FgHiGreen).Sprint("tor")
	case strings.Contains(transportStr, "cdn"):
		return color.New(color.FgGreen).Sprint("cdn")
	case strings.Contains(transportStr, "reverse proxy"):
		return color.New(color.FgHiCyan).Sprint("rproxy")
	case strings.Contains(transportStr, "auto proxy"):
		return color.New(color.FgHiYellow).Sprint("aproxy")
	case strings.Contains(transportStr, "proxy"):
		return color.New(color.FgHiYellow).Sprint("proxy")
	default:
		return color.New(color.FgHiWhite).Sprint("unknown")
	}
}

func cliPrintHelper(format string, a []interface{}, msgColor *color.Color, logPrefix string, alert bool) {
	logMsg := msgColor.Sprintf(format, a...)
	if alert {
		Emp3r0rConsole.Printf("%s\n", logMsg)
	} else {
		Emp3r0rConsole.TransientPrintf("%s\n", logMsg)
	}

	if IsAPIEnabled {
		var resp APIResponse
		msg := GetDateTime() + " " + logPrefix + ": " + fmt.Sprintf(format, a...)
		resp.MsgData = []byte(msg)
		resp.Alert = alert
		resp.MsgType = LOG
		data, jsonMarshalErr := json.Marshal(resp)
		if jsonMarshalErr != nil {
			Emp3r0rConsole.Printf("cliPrintHelper: %v\n", jsonMarshalErr)
			return
		}
		_, jsonMarshalErr = APIConn.Write([]byte(data))
		if jsonMarshalErr != nil {
			Emp3r0rConsole.Printf("cliPrintHelper: %v\n", jsonMarshalErr)
		}
	}
}

func CliPrintDebug(format string, a ...interface{}) {
	if DebugLevel >= 3 {
		cliPrintHelper(format, a, color.New(color.FgBlue, color.Italic), "DEBUG", false)
	}
}

func CliPrintInfo(format string, a ...interface{}) {
	if DebugLevel >= 2 {
		cliPrintHelper(format, a, color.New(color.FgBlue), "INFO", false)
	}
}

func CliPrintWarning(format string, a ...interface{}) {
	if DebugLevel >= 1 {
		cliPrintHelper(format, a, color.New(color.FgHiYellow), "WARN", false)
	}
}

func CliPrint(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiCyan), "PRINT", false)
}

func CliMsg(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiCyan), "MSG", false)
}

func CliAlert(textColor color.Attribute, format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(textColor, color.Bold), "ALERT", false)
}

func CliPrintSuccess(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiGreen, color.Bold), "SUCCESS", true)
}

func CliFatalError(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), "ERROR", true)
	CliMsg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	log.Fatal(color.New(color.Bold, color.FgHiRed).Sprintf(format, a...))
}

func CliPrintError(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiRed, color.Bold), "ERROR", true)
}

// CliListOptions list currently available options for `set`
func CliListOptions(cmd *cobra.Command, args []string) {
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

	for opt_name, opt := range CurrentModuleOptions {
		if opt != nil {
			opts[opt_name] = opt.Name
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
	table.SetColWidth(50)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})
	table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor})

	// fill table
	module_obj := emp3r0r_def.Modules[CurrentMod]
	if module_obj == nil {
		CliPrintError("Module %s not found", CurrentMod)
		return
	}
	for opt_name, opt_obj := range module_obj.Options {
		help := "N/A"
		if opt_obj == nil {
			continue
		}
		help = opt_obj.OptDesc
		switch opt_name {
		case "module":
			help = "Selected module"
		case "target":
			help = "Selected target"
		}
		val := ""
		currentOpt, ok := CurrentModuleOptions[opt_name]
		if ok {
			val = currentOpt.Val
		}

		tdata = append(tdata,
			[]string{
				util.SplitLongLine(opt_name, 50),
				util.SplitLongLine(help, 50),
				util.SplitLongLine(val, 50),
			})
	}
	table.AppendBulk(tdata)
	table.Render()
	out := tableString.String()
	AdaptiveTable(out)
	CliPrint("\n%s", out)
}

// CliBanner prints banner
func CliBanner(console *console.Console) {
	data, encodingErr := base64.StdEncoding.DecodeString(cliBannerB64)
	if encodingErr != nil {
		log.Fatalf("failed to print banner: %v", encodingErr.Error())
	}
	banner := strings.Builder{}
	banner.Write(data)

	// print banner line by line
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
		log.Fatalf("Failed to parse CA cert: %v", encodingErr)
	}
	c2_names := tun.NamesInCert(ServerCrtFile)
	if len(c2_names) <= 0 {
		log.Fatalf("C2 has no names?")
	}
	name_list := strings.Join(c2_names, ", ")

	say, encodingErr := cow.Say(fmt.Sprintf("welcome! you are using version %s,\n"+
		"C2 listening on *:%s,\n"+
		"Shadowsocks server port *:%s,\n"+
		"KCP port *:%s,\n"+
		"C2 names: %s\n"+
		"CA fingerprint: %s",
		emp3r0r_def.Version,
		RuntimeConfig.CCPort,
		RuntimeConfig.ShadowsocksServerPort,
		RuntimeConfig.KCPServerPort,
		name_list,
		RuntimeConfig.CAFingerprint))
	if encodingErr != nil {
		log.Fatalf("CowSay: %v", encodingErr)
	}
	banner.WriteString(color.CyanString("%s\n\n", say))
	fmt.Print(banner.String())
}

// CliPrettyPrint prints two-column help info
func CliPrettyPrint(header1, header2 string, map2write *map[string]string) {
	if IsAPIEnabled {
		// send to socket
		var resp APIResponse
		msg, marshalErr := json.Marshal(map2write)
		if marshalErr != nil {
			Emp3r0rConsole.Printf("CliPrettyPrint: %v\n", marshalErr)
		}
		resp.MsgData = msg
		resp.Alert = false
		resp.MsgType = JSON
		data, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			Emp3r0rConsole.Printf("CliPrettyPrint: %v\n", marshalErr)
		}
		_, marshalErr = APIConn.Write([]byte(data))
		if marshalErr != nil {
			Emp3r0rConsole.Printf("CliPrettyPrint: %v\n", marshalErr)
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
	table.SetColWidth(50)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	table.SetColumnColor(tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor})

	// fill table
	for c1, c2 := range *map2write {
		tdata = append(tdata,
			[]string{util.SplitLongLine(c1, 50), util.SplitLongLine(c2, 50)})
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
		for _, opt := range CurrentModuleOptions {
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

		for opt := range CurrentModuleOptions {
			names = append(names, opt)
		}
		return names
	}
}

// remote autocomplete items in $PATH
func listAgentExes(agent *emp3r0r_def.Emp3r0rAgent) []string {
	CliPrintDebug("Listing agent %s's exes in PATH", agent.Tag)
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
func autoCompleteAgentExes(agent *emp3r0r_def.Emp3r0rAgent) {
	// exes := listAgentExes(agent)
	// temp_CmdCompls := InitCmdCompls
	//
	// is_exe_same_as_cmd := func(exe string) bool {
	// 	for _, cmd := range CLICommands {
	// 		if exe == cmd {
	// 			return true
	// 		}
	// 	}
	// 	return false
	// }
	//
	// for _, exe := range exes {
	// 	if is_exe_same_as_cmd(exe) {
	// 		CliPrintDebug("Exe %s exists in CLI commands, skipping", strconv.Quote(exe))
	// 		continue
	// 	}
	// 	temp_CmdCompls = append(temp_CmdCompls, readline.PcItem(exe))
	// }
	//
	// CmdCompls = temp_CmdCompls
	// CliCompleter.SetChildren(CmdCompls)
}

// remote ls autocomplete items in current directory
func listRemoteDir() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		cmd := fmt.Sprintf("%s --path .", emp3r0r_def.C2CmdListDir)
		cmd_id := uuid.NewString()
		err := SendCmdToCurrentTarget(cmd, cmd_id)
		if err != nil {
			CliPrintDebug("Cannot list remote directory: %v", err)
			return names
		}
		remote_entries := []string{}
		for i := 0; i < 100; i++ {
			if res, exists := CmdResults[cmd_id]; exists {
				remote_entries = strings.Split(res, "\n")
				CmdResultsMutex.Lock()
				delete(CmdResults, cmd_id)
				CmdResultsMutex.Unlock()
				break
			}
			time.Sleep(100 * time.Millisecond)
			if i == 99 {
				CliPrintDebug("Timeout listing remote directory")
				return names
			}
		}
		if len(remote_entries) == 0 {
			CliPrintDebug("Nothing in remote directory")
			return names
		}
		for _, name := range remote_entries {
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

func setDebugLevel(cmd *cobra.Command, args []string) {
	level, err := cmd.Flags().GetInt("level")
	if err != nil {
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
