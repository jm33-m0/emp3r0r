package cc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/bettercap/readline"
	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

const PromptName = "emp3r0r"

var (
	// CliCompleter holds all command completions
	CliCompleter = readline.NewPrefixCompleter()

	// CmdCompls completions for readline
	CmdCompls []readline.PrefixCompleterInterface

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
			readline.PcItemDynamic(listDir())),

		readline.PcItem("mv",
			readline.PcItemDynamic(listDir())),

		readline.PcItem("mkdir",
			readline.PcItemDynamic(listDir())),

		readline.PcItem("cp",
			readline.PcItemDynamic(listDir())),

		readline.PcItem("cd",
			readline.PcItemDynamic(listDir())),

		readline.PcItem("get",
			readline.PcItemDynamic(listDir())),

		readline.PcItem("vim",
			readline.PcItemDynamic(listDir())),

		readline.PcItem("put",
			readline.PcItemDynamic(listFiles("./"))),

		readline.PcItem(HELP,
			readline.PcItemDynamic(listMods())),

		readline.PcItem("target",
			readline.PcItemDynamic(listTargetIndexTags())),

		readline.PcItem("label",
			readline.PcItemDynamic(listTargetIndexTags())),

		readline.PcItem("delete_port_fwd",
			readline.PcItemDynamic(listPortMappings())),
	}

	for cmd := range Commands {
		if cmd == "set" ||
			cmd == "use" ||
			cmd == "get" ||
			cmd == "vim" ||
			cmd == "put" ||
			cmd == "cp" ||
			cmd == "mkdir" ||
			cmd == "target" ||
			cmd == "label" ||
			cmd == "delete_port_fwd" ||
			cmd == "rm" ||
			cmd == "mv" ||
			cmd == "cd" ||
			cmd == HELP {
			continue
		}
		CmdCompls = append(CmdCompls, readline.PcItem(cmd))
	}
	CmdCompls = append(CmdCompls, readline.PcItemDynamic(listFiles("./")))
	CliCompleter.SetChildren(CmdCompls)

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
		HistoryFile:     "./emp3r0r.history",
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
			os.Exit(0)

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
		os.Exit(0)
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
	dynamicPrompt := fmt.Sprintf("%s @%s (%s) "+color.HiCyanString("> "),
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

// CliMsg print log in cyan, regardless of debug level
func CliMsg(format string, a ...interface{}) {
	log.Println(color.CyanString(format, a...))
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

// CliYesNo prompt for a y/n answer from user
func CliYesNo(prompt string) bool {
	// always return true if there's no way to show prompt
	if IsAPIEnabled {
		return true
	}

	EmpReadLine.SetPrompt(color.CyanString(prompt + "? [y/N] "))
	EmpReadLine.Config.EOFPrompt = ""
	EmpReadLine.Config.InterruptPrompt = ""

	defer EmpReadLine.SetPrompt(EmpPrompt)

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

	CliPrettyPrint("Option", "Value", &opts)
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
	color.Cyan("version: %s\n\n", emp3r0r_data.Version)
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

	cnt := 18
	sep := strings.Repeat(" ", cnt)
	color.Cyan("%s%s%s\n", header1, sep, header2)

	color.Cyan("%s%s%s\n", strings.Repeat("=", len(header1)), sep, strings.Repeat("=", len(header2)))
	fmt.Println("")

	for c1, c2 := range *map2write {
		cnt = len(header1) + 18 - len(c1) // NOTE cannot be too long or cnt can be negative
		sep = strings.Repeat(" ", cnt)
		color.Cyan("%s%s%s\n", c1, sep, c2)
	}
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
IG1hZGUgYnkgbGludXggdXNlcgoKYnkgam0zMy1uZwoKaHR0cHM6Ly9naXRodWIuY29tL2ptMzMt
bTAvZW1wM3IwcgoKCg==
`

// autocomplete module options
func listValChoices() func(string) []string {
	return func(line string) []string {
		switch CurrentMod {
		case emp3r0r_data.ModCMD_EXEC:
			return Options["cmd_to_exec"].Vals
		case emp3r0r_data.ModSHELL:
			ret := append(Options["shell"].Vals, Options["port"].Vals...)
			return ret
		case emp3r0r_data.ModCLEAN_LOG:
			return Options["keyword"].Vals
		case emp3r0r_data.ModLPE_SUGGEST:
			return Options["lpe_helper"].Vals
		case emp3r0r_data.ModPERSISTENCE:
			return Options["method"].Vals
		case emp3r0r_data.ModPROXY:
			return append(Options["status"].Vals, Options["port"].Vals...)
		case emp3r0r_data.ModINJECTOR:
			return append(Options["pid"].Vals, Options["method"].Vals...)
		case emp3r0r_data.ModPORT_FWD:
			ret := append(Options["listen_port"].Vals, Options["to"].Vals...)
			ret = append(ret, Options["switch"].Vals...)
			return ret
		}

		return nil
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

// autocomplete items in current directory
func listDir() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		for _, name := range LsDir {
			names = append(names, name)
		}
		return names
	}
}

// Function constructor - constructs new function for listing given directory
func listFiles(path string) func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		files, _ := ioutil.ReadDir(path)
		for _, f := range files {
			names = append(names, f.Name())
		}
		return names
	}
}
