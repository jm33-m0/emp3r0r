package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	cowsay "github.com/Code-Hex/Neo-cowsay/v2"
	"github.com/alecthomas/chroma/quick"
	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/core"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/server"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/reeflective/console"
)

const AppName = "emp3r0r"

// Emp3r0rConsole: the main console interface
var Emp3r0rConsole = console.New(AppName)

// CliMain launches the commandline UI
func CliMain() {
	// start all services
	go server.StartTLSServer()
	go server.KCPC2ListenAndServe()
	go modules.InitModules()

	// unlock incomplete downloads
	err := core.UnlockDownloads()
	if err != nil {
		logging.Debugf("UnlockDownloads: %v", err)
	}
	mainMenu := Emp3r0rConsole.NewMenu("")
	Emp3r0rConsole.SetPrintLogo(CliBanner)

	// History
	histFile := fmt.Sprintf("%s/%s.history", def.EmpWorkSpace, AppName)
	mainMenu.AddHistorySourceFile(AppName, histFile)

	// Commands
	mainMenu.SetCommands(Emp3r0rCommands(Emp3r0rConsole))

	// Interrupts
	mainMenu.AddInterrupt(io.EOF, exitEmp3r0r)

	// prompt
	prompt := mainMenu.Prompt()
	prompt.Primary = SetDynamicPrompt
	prompt.Secondary = func() string { return ">" }
	prompt.Right = func() string { return color.CyanString(time.Now().Format("03:04:05")) }
	prompt.Transient = func() string { return ">>>" }
	Emp3r0rConsole.NewlineBefore = true
	Emp3r0rConsole.NewlineAfter = true
	Emp3r0rConsole.NewlineWhenEmpty = true

	// Shell features
	Emp3r0rConsole.Shell().SyntaxHighlighter = highLighter
	Emp3r0rConsole.Shell().Config.Set("history-autosuggest", true)
	Emp3r0rConsole.Shell().Config.Set("autopairs", true)
	Emp3r0rConsole.Shell().Config.Set("colored-completion-prefix", true)
	Emp3r0rConsole.Shell().Config.Set("colored-stats", true)
	Emp3r0rConsole.Shell().Config.Set("completion-ignore-case", true)
	Emp3r0rConsole.Shell().Config.Set("usage-hint-always", true)

	// Tmux setup, we will need to log to tmux window
	err = cli.TmuxInitWindows()
	if err != nil {
		logging.Fatalf("Fatal TMUX error: %v, please run `tmux kill-session -t emp3r0r` and re-run emp3r0r", err)
	}

	// when the console is closed, deinit tmux windows
	defer cli.TmuxDeinitWindows()

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

	if def.ActiveAgent != nil && agent_util.IsAgentExist(def.ActiveAgent) {
		shortName = strings.Split(def.ActiveAgent.Tag, "-agent")[0]
		if def.ActiveAgent.HasRoot {
			prompt_arrow = color.New(color.Bold, color.FgHiGreen).Sprint("\n# ")
			prompt_name = color.New(color.Bold, color.FgBlack, color.BgHiGreen).Sprint(AppName)
		}
		transport = getTransport(def.ActiveAgent.Transport)
	}
	agent_name := color.New(color.FgCyan, color.Underline).Sprint(shortName)
	mod_name := color.New(color.FgHiBlue).Sprint(def.ActiveModule)

	dynamicPrompt := fmt.Sprintf("%s - %s @%s (%s) "+prompt_arrow,
		prompt_name,
		transport,
		agent_name,
		mod_name,
	)
	return dynamicPrompt
}

func getTransport(transportStr string) string {
	transportStr = strings.ToLower(transportStr)
	switch {
	case strings.Contains(transportStr, "http2"):
		return color.New(color.FgHiBlue).Sprint("http2")
	case strings.Contains(transportStr, "kcp"):
		return color.New(color.FgHiMagenta).Sprint("kcp")
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

// CliBanner prints banner
func CliBanner(console *console.Console) {
	const logo string = `
  ______  ______  ______  ______  ______
 /      \/      \/      \/      \/      \
|  e   m |  p   3 |  r   0 |  r    |      |
 \______/ \______/ \______/ \______/ \______/
        A Linux C2 made by a Linux user
`
	banner := strings.Builder{}
	banner.WriteString(color.RedString("%s", logo))
	cow, encodingErr := cowsay.New(
		cowsay.BallonWidth(100),
		cowsay.Random(),
	)
	if encodingErr != nil {
		logging.Fatalf("CowSay: %v", encodingErr)
	}

	// C2 names
	c2_names := tun.NamesInCert(def.ServerCrtFile)
	if len(c2_names) <= 0 {
		logging.Fatalf("C2 has no names?")
	}
	name_list := strings.Join(c2_names, ", ")

	say, encodingErr := cow.Say(fmt.Sprintf("Welcome! You are using emp3r0r %s,\n"+
		"C2 listening on: *:%s,\n"+
		"KCP: *:%s,\n"+
		"C2 names: %s\n"+
		"CA Fingerprint: %s",
		emp3r0r_def.Version,
		def.RuntimeConfig.CCPort,
		def.RuntimeConfig.KCPServerPort,
		name_list,
		def.RuntimeConfig.CAFingerprint,
	))
	if encodingErr != nil {
		logging.Fatalf("CowSay: %v", encodingErr)
	}
	banner.WriteString(color.BlueString("%s\n\n", say))
	fmt.Print(banner.String())
}
