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
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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
	client.HTTPClient = createOperatorHTTPClient()
	// The operator's stable identity is its provisioned WireGuard IP: the C2
	// sees that IP as the tunnel peer address, so both sides agree on identity
	// WITHOUT an extra handshake. Local/no-WireGuard mode falls back to a
	// random session id.
	if wireguard.WgOperator != nil && wireguard.WgOperatorIP != "" {
		client.SessionID = wireguard.WgOperatorIP
	} else {
		client.SessionID = uuid.NewString()
	}

	OperatorAddr = fmt.Sprintf("%s:%d", wireguard.WgServerIP, OperatorPort)
	logging.Infof("Operator's address: %s", OperatorAddr)

	// Update operator's IP to Wireguard IP
	client.RootURL = fmt.Sprintf("http://%s", OperatorAddr)
	logging.Infof("Operator's WireGuard address: %s", client.RootURL)

	// set up command senders
	ftp.ExecCmd = controllers.ExecuteCommand
	modules.CmdSender = controllers.ExecuteCommand
	// track per-agent operator idle (time since the agent last received a
	// command from this operator)
	controllers.OnCommandSent = markAgentCommandSent
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
	// Load modules before command tree creation so module_name commands and flags exist for completion.
	modules.InitModules()
	// Hot-reload module dir changes: new/edited/removed module configs are
	// re-synced into def.Modules (and thus into the command tree, which is
	// rebuilt from it on every prompt cycle). Only the changed modules are
	// logged.
	modules.StartModuleWatch()
	mainMenu := EMP3R0R_CONSOLE.ActiveMenu()
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
	// Also run tmux cleanup for explicit process exits (live.Exit), which skip
	// deferred functions because they terminate the process.
	live.OnShutdown(cli.TmuxDeinitWindows)

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

const (
	promptRawLimit  = 2048 // cap hostile metadata before sanitizing it
	promptUserLimit = 96
	promptHostLimit = 128
	promptCWDLimit  = 256
	promptUnknown   = "unknown"
)

// promptClean bounds and sanitizes one agent-controlled value for display.
// Agent metadata is hostile: it must never carry terminal escapes, control
// bytes, or unbounded text into the operator console.
func promptClean(value string, limit int) string {
	if len(value) > promptRawLimit {
		value = value[:promptRawLimit]
	}
	clean := util.SanitizeOneLine(value)
	if limit <= 0 {
		return clean
	}
	runes := []rune(clean)
	if len(runes) > limit {
		clean = string(runes[:limit]) + "..."
	}
	return clean
}

// promptAgentUser extracts the account/domain portion of the verbose user
// metadata ("NAME (home), uid=..., gid=..."). On Windows NAME is normally
// DOMAIN\user, so the domain is displayed with the account.
func promptAgentUser(agent *def.Emp3r0rAgent) string {
	if agent == nil {
		return promptUnknown
	}
	raw := promptClean(agent.User, promptRawLimit)
	if raw != "" && !strings.HasPrefix(strings.ToLower(raw), "not available") {
		fields := strings.Fields(raw)
		if len(fields) > 0 {
			name := strings.TrimSuffix(strings.Trim(fields[0], "()[],"), ",")
			if name != "" {
				return promptClean(name, promptUserLimit)
			}
		}
	}

	// Fallback to Name ("host/user" or "host/DOMAIN/user"). The part after
	// the first separator keeps the domain when the agent reported one.
	name := promptClean(agent.Name, promptRawLimit)
	if i := strings.IndexAny(name, "/\\"); i >= 0 && i+1 < len(name) {
		if user := promptClean(name[i+1:], promptUserLimit); user != "" {
			return user
		}
	}
	return promptUnknown
}

// promptAgentHost returns the target hostname, falling back to the first
// component of Name when Hostname is absent.
func promptAgentHost(agent *def.Emp3r0rAgent) string {
	if agent == nil {
		return promptUnknown
	}
	if host := promptClean(agent.Hostname, promptHostLimit); host != "" {
		return host
	}
	name := promptClean(agent.Name, promptRawLimit)
	if i := strings.IndexAny(name, "/\\"); i > 0 {
		if host := promptClean(name[:i], promptHostLimit); host != "" {
			return host
		}
	}
	return promptUnknown
}

func promptAgentCWD(agent *def.Emp3r0rAgent) string {
	if agent == nil {
		return promptUnknown
	}
	if cwd := promptClean(agent.CWD, promptCWDLimit); cwd != "" {
		return cwd
	}
	return promptUnknown
}

// promptAgentTag accepts only the C2-derived identifier shape. An invalid tag
// must never reach the console, even if a future trust boundary regresses.
func promptAgentTag(agent *def.Emp3r0rAgent) string {
	if agent != nil && util.IsAgentID(agent.Tag) {
		return agent.Tag
	}
	return promptUnknown
}

// promptAgentIdentity returns sanitized user, host, and cwd components.
func promptAgentIdentity(agent *def.Emp3r0rAgent) (user, host, cwd string) {
	return promptAgentUser(agent), promptAgentHost(agent), promptAgentCWD(agent)
}

// SetDynamicPrompt set prompt with target and working-directory info.
// Every agent-derived component is sanitized and bounded before it is placed
// in the prompt; none of it is interpreted as a command or format string.
func SetDynamicPrompt() string {
	shortName := "local" // if no target is selected
	prompt_arrow := color.New(color.Bold, color.FgHiCyan).Sprintf("\n$ ")
	prompt_name := color.New(color.Bold, color.FgBlack, color.BgHiWhite).Sprint(AppName)
	transport := color.New(color.FgRed).Sprint("local")
	target := color.New(color.FgHiBlue).Sprint("cwd:local")

	if active := live.GetActiveAgent(); active != nil {
		shortName = promptAgentTag(active)
		if active.HasRoot {
			prompt_arrow = color.New(color.Bold, color.FgHiGreen).Sprintf("\n# ")
			prompt_name = color.New(color.Bold, color.FgBlack, color.BgHiGreen).Sprint(AppName)
		}
		transport = getTransport(active.Transport)
		user, host, cwd := promptAgentIdentity(active)
		identity := color.New(color.FgCyan).Sprintf("%s@%s", user, host)
		target = identity + ":" + color.New(color.FgHiBlue).Sprint(cwd)
	}
	agent_name := color.New(color.FgCyan, color.Underline).Sprint(shortName)

	dynamicPrompt := fmt.Sprintf(
		"%s - %s @%s %s "+prompt_arrow,
		prompt_name,
		transport,
		agent_name,
		target,
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

func valueOrUnset(value string) string {
	if value == "" {
		return "unset"
	}
	return value
}

func formatRouteSummary() string {
	routes := live.RuntimeConfig.C2Routes
	return fmt.Sprintf(
		"checkin=%s msg=%s ftp=%s www=%s proxy=%s",
		valueOrUnset(routes.Checkin),
		valueOrUnset(routes.Msg),
		valueOrUnset(routes.FTP),
		valueOrUnset(routes.WWW),
		valueOrUnset(routes.Proxy),
	)
}

func formatBannerSummary() string {
	return fmt.Sprintf(
		"Config: mode=%s http=%s c2=%s relay=%s\n"+
			"Routes: %s\n"+
			"Paths: prefix=%s data=%s workspace=%s log=%s\n"+
			"Server: %s\n"+
			"Operator: %s\n"+
			"Server Key: %s",
		valueOrUnset(live.RuntimeConfig.C2ChannelMode),
		valueOrUnset(live.RuntimeConfig.CCHTTPPort),
		valueOrUnset(live.RuntimeConfig.CCH2Port),
		valueOrUnset(live.RuntimeConfig.P2PRelayPort),
		formatRouteSummary(),
		valueOrUnset(live.Prefix),
		valueOrUnset(live.EmpDataDir),
		valueOrUnset(live.EmpWorkSpace),
		valueOrUnset(live.EmpLogFile),
		valueOrUnset(ServerIP),
		valueOrUnset(OperatorAddr),
		valueOrUnset(ServerKey),
	)
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

	say, encodingErr := cow.Say(fmt.Sprintf(
		"Welcome! You are using emp3r0r %s\n"+
			"C2 Names: %s\n"+
			"%s",
		def.BuildVersion,
		name_list,
		formatBannerSummary(),
	))
	if encodingErr != nil {
		logging.Fatalf("CowSay: %v", encodingErr)
	}
	banner.WriteString(color.BlueString("%s\n\n", say))
	logging.RawPrintf(nil, "%s", banner.String())
}
