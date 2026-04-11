package operator

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	cowsay "github.com/Code-Hex/Neo-cowsay/v2"
	"github.com/alecthomas/chroma/quick"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/reeflective/console"
)

const AppName = "emp3r0r"

var (
	// EMP3R0R_CONSOLE: the main console interface
	EMP3R0R_CONSOLE = console.New(AppName)

	// SERVER_IP: operator server IP, non-WireGuard IP
	ServerIP string
	// SERVER_KEY: operator server's public key
	ServerKey string
	// OPERATOR_ADDR: operator server address
	OperatorAddr string
	// OPERATOR_PORT: operator server port
	OperatorPort int

	// AgentRefreshCh triggers agent list refresh
	AgentRefreshCh = make(chan struct{}, 1)
)

func backgroundJobs() {
	var err error
	client.HTTPClient, err = createMTLSHttpClient()
	if err != nil {
		logging.Fatalf("Failed to create HTTP client: %v", err)
	}
	client.SessionID = uuid.NewString()

	OperatorAddr = fmt.Sprintf("%s:%d", netutil.WgServerIP, OperatorPort)
	logging.Infof("Operator's address: %s", OperatorAddr)

	// Update operator's IP to Wireguard IP
	client.RootURL = fmt.Sprintf("https://%s", OperatorAddr)
	logging.Infof("Operator's WireGuard address: %s", client.RootURL)

	// set up command senders
	ftp.ExecCmd = controllers.ExecuteCommand
	modules.CmdSender = controllers.ExecuteCommand

	// init modules by querying server for available modules
	go modules.InitModules()
	// refresh agent list every 10 seconds
	go agentListRefresher()
	// handle messages from operator
	go client.StartMessageTunnel(processAgentData, func(err error) {
		logging.Errorf("Message tunnel: %v", err)
	})
}

// CliMain launches the commandline UI
func CliMain(wg_server_ip string, wg_server_port int) {
	defer func() {
		if r := recover(); r != nil {
			logging.Fatalf("CliMain panicked: %v", r)
		}
		logging.Infof("CliMain resumed (or returned normally)")
	}()
	OperatorPort = wg_server_port + 1
	ServerIP = wg_server_ip

	// unlock incomplete downloads
	err := tools.UnlockDownloads()
	if err != nil {
		logging.Debugf("UnlockDownloads: %v", err)
	}
	mainMenu := EMP3R0R_CONSOLE.NewMenu("")
	EMP3R0R_CONSOLE.SetPrintLogo(CliBanner)

	// History
	histFile := fmt.Sprintf("%s/%s.history", live.EmpWorkSpace, AppName)
	mainMenu.AddHistorySourceFile(AppName, histFile)

	// Commands
	mainMenu.SetCommands(Emp3r0rCommands(EMP3R0R_CONSOLE))

	// Interrupts
	mainMenu.AddInterrupt(io.EOF, exitEmp3r0r)

	// prompt
	prompt := mainMenu.Prompt()
	prompt.Primary = SetDynamicPrompt
	prompt.Secondary = func() string { return ">" }
	prompt.Right = func() string { return color.CyanString(time.Now().Format("03:04:05")) }
	prompt.Transient = func() string { return ">>>" }
	EMP3R0R_CONSOLE.NewlineBefore = true
	EMP3R0R_CONSOLE.NewlineAfter = true
	EMP3R0R_CONSOLE.NewlineWhenEmpty = true

	// Shell features
	EMP3R0R_CONSOLE.Shell().SyntaxHighlighter = highLighter
	EMP3R0R_CONSOLE.Shell().Config.Set("history-autosuggest", true)
	EMP3R0R_CONSOLE.Shell().Config.Set("autopairs", true)
	EMP3R0R_CONSOLE.Shell().Config.Set("colored-completion-prefix", true)
	EMP3R0R_CONSOLE.Shell().Config.Set("colored-stats", true)
	EMP3R0R_CONSOLE.Shell().Config.Set("completion-ignore-case", true)
	EMP3R0R_CONSOLE.Shell().Config.Set("usage-hint-always", true)

	// Tmux setup, we will need to log to tmux window
	cli.CAT = live.CAT // emp3r0r-cat is set up in internal/live/config.go
	err = cli.TmuxInitWindows()
	if err != nil {
		logging.Fatalf("Fatal TMUX error: %v, please run `tmux kill-session -t emp3r0r` and re-run emp3r0r", err)
	}

	// Log to tmux window as well
	f, err := os.OpenFile(cli.OutputPane.TTY, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		logging.Fatalf("Failed to open tmux pane: %v", err)
	}
	logging.AddWriter(f)

	// when the console is closed, deinit tmux windows
	defer cli.TmuxDeinitWindows()

	// Background jobs
	backgroundJobs()

	// Run the console
	logging.Fatal(EMP3R0R_CONSOLE.Start())
}

func highLighter(line []rune) string {
	var highlightedStr strings.Builder
	err := quick.Highlight(&highlightedStr, string(line), "fish", "terminal256", "tokyonight-moon")
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

	if live.ActiveAgent != nil {
		// live.ActiveAgent is already sanitized at storage time
		shortName = strings.Split(live.ActiveAgent.Tag, "-agent")[0]
		if live.ActiveAgent.HasRoot {
			prompt_arrow = color.New(color.Bold, color.FgHiGreen).Sprint("\n# ")
			prompt_name = color.New(color.Bold, color.FgBlack, color.BgHiGreen).Sprint(AppName)
		}
		transport = getTransport(live.ActiveAgent.Transport)
	}
	agent_name := color.New(color.FgCyan, color.Underline).Sprint(shortName)
	mod := "none"
	if live.ActiveModule != nil {
		mod = live.ActiveModule.Name
	}
	mod_name := color.New(color.FgHiBlue).Sprint(mod)

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
	case strings.Contains(transportStr, "http"):
		return color.New(color.FgHiCyan).Sprint("http")
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
	c2_names := transport.NamesInCert(transport.ServerCrtFile)
	if len(c2_names) <= 0 {
		logging.Fatalf("C2 has no names?")
	}
	name_list := strings.Join(c2_names, ", ")

	say, encodingErr := cow.Say(fmt.Sprintf("Welcome! You are using emp3r0r %s,\n"+
		"C2: *:%s,\n"+
		"KCP: *:%s,\n"+
		"C2 Names: %s\n"+
		"Server: %s (%s)\n"+
		"Server Key: %s",
		def.Version,
		live.RuntimeConfig.CCPort,
		live.RuntimeConfig.KCPServerPort,
		name_list,
		OperatorAddr,
		ServerIP,
		ServerKey,
	))
	if encodingErr != nil {
		logging.Fatalf("CowSay: %v", encodingErr)
	}
	banner.WriteString(color.BlueString("%s\n\n", say))
	logging.RawPrintf(nil, "%s", banner.String())
}
