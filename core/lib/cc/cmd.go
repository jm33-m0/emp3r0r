//go:build linux
// +build linux

package cc

import (
	"os"
	"sync"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/reeflective/console"
	"github.com/reeflective/console/commands/readline"
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
			GroupID: "core",
			Short:   "Exit emp3r0r",
			Run: func(cmd *cobra.Command, args []string) {
				exitEmp3r0r(app)
			},
		}
		rootCmd.AddCommand(exitCmd)

		helpCmd := &cobra.Command{
			Use:     "help",
			GroupID: "core",
			Short:   "Display help for a module",
			Example: "help --module gen_agent",
			Run:     CmdHelp,
		}
		helpCmd.Flags().StringP("module", "m", "", "Module name")
		rootCmd.AddCommand(helpCmd)

		setDebuglevelCmd := &cobra.Command{
			Use:     "debug",
			GroupID: "core",
			Short:   "Set debug level: 0 (least verbose) to 3 (most verbose)",
			Example: "debug --level 3",
			Run:     setDebugLevel,
		}
		setDebuglevelCmd.Flags().IntP("level", "l", 0, "Debug level")
		rootCmd.AddCommand(setDebuglevelCmd)

		useModuleCmd := &cobra.Command{
			Use:     "use",
			GroupID: "module",
			Short:   "Use a module",
			Example: "use --module gen_agent",
			Run:     setActiveModule,
		}
		useModuleCmd.Flags().StringP("module", "m", "", "Module name")
		rootCmd.AddCommand(useModuleCmd)

		infoCmd := &cobra.Command{
			Use:     "info",
			GroupID: "module",
			Short:   "What options do we have?",
			Run:     listModOptionsTable,
		}
		rootCmd.AddCommand(infoCmd)

		setCmd := &cobra.Command{
			Use:     "set",
			GroupID: "module",
			Short:   "Set an option of the current module",
			Example: "set --option cc_host --value emp3r0r.com",
			Run:     setOptValCmd,
		}
		setCmd.Flags().StringP("option", "o", "", "Option name")
		setCmd.Flags().StringP("value", "v", "", "Option value")
		rootCmd.AddCommand(setCmd)

		runCmd := &cobra.Command{
			Use:     "run",
			GroupID: "module",
			Short:   "Run the current module",
			Run:     ModuleRun,
		}
		rootCmd.AddCommand(runCmd)

		targetCmd := &cobra.Command{
			Use:     "target",
			GroupID: "agent",
			Short:   "Set active target",
			Example: "target --id 0",
			Run:     setActiveTarget,
		}
		targetCmd.Flags().StringP("id", "i", "", "Target ID")
		rootCmd.AddCommand(targetCmd)

		upgradeAgentCmd := &cobra.Command{
			Use:     "upgrade_agent",
			GroupID: "agent",
			Short:   "Upgrade agent on selected target, put agent binary in /tmp/emp3r0r/www/agent first",
			Run:     UpgradeAgent,
		}
		rootCmd.AddCommand(upgradeAgentCmd)

		upgradeCCCmd := &cobra.Command{
			Use:     "upgrade_cc",
			GroupID: "c2",
			Short:   "Upgrade emp3r0r from GitHub",
			Example: "upgrade_cc [--force]",
			Run:     UpdateCC,
		}
		rootCmd.AddCommand(upgradeCCCmd)

		fileManagerCmd := &cobra.Command{
			Use:     "file_manager",
			GroupID: "filesystem",
			Short:   "Browse remote files in your local file manager with SFTP protocol",
			Run:     OpenFileManager,
		}
		rootCmd.AddCommand(fileManagerCmd)

		lsCmd := &cobra.Command{
			Use:     "ls",
			GroupID: "filesystem",
			Short:   "List a directory of selected agent, without argument it lists current directory",
			Example: "ls --path /tmp",
			Run:     ls,
		}
		lsCmd.Flags().StringP("path", "p", "", "Path to list")
		rootCmd.AddCommand(lsCmd)

		cdCmd := &cobra.Command{
			Use:     "cd",
			GroupID: "filesystem",
			Short:   "Change current working directory of selected agent",
			Run:     cd,
		}
		cdCmd.Flags().StringP("path", "p", "", "Path to change to")
		rootCmd.AddCommand(cdCmd)

		cpCmd := &cobra.Command{
			Use:     "cp",
			GroupID: "filesystem",
			Short:   "Copy a file to another location on selected target",
			Example: "cp --src /tmp/1.txt --dst /tmp/2.txt",
			Run:     cp,
		}
		cpCmd.Flags().StringP("src", "s", "", "Source file")
		cpCmd.Flags().StringP("dst", "d", "", "Destination file")
		rootCmd.AddCommand(cpCmd)

		mvCmd := &cobra.Command{
			Use:     "mv",
			GroupID: "filesystem",
			Short:   "Move a file to another location on selected target",
			Example: "mv --src /tmp/1.txt --dst /tmp/2.txt",
			Run:     mv,
		}
		mvCmd.Flags().StringP("src", "s", "", "Source file")
		mvCmd.Flags().StringP("dst", "d", "", "Destination file")
		rootCmd.AddCommand(mvCmd)

		rmCmd := &cobra.Command{
			Use:     "rm",
			GroupID: "filesystem",
			Short:   "Delete a file/directory on selected agent",
			Example: "rm --path /tmp/1.txt",
			Run:     rm,
		}
		rmCmd.Flags().StringP("path", "p", "", "Path to delete")
		rootCmd.AddCommand(rmCmd)

		mkdirCmd := &cobra.Command{
			Use:     "mkdir",
			GroupID: "filesystem",
			Short:   "Create new directory on selected agent",
			Example: "mkdir --path /tmp/newdir",
			Run:     mkdir,
		}
		mkdirCmd.Flags().StringP("path", "p", "", "Path to create")
		rootCmd.AddCommand(mkdirCmd)

		pwdCmd := &cobra.Command{
			Use:     "pwd",
			GroupID: "filesystem",
			Short:   "Current working directory of selected agent",
			Run:     pwd,
		}
		rootCmd.AddCommand(pwdCmd)

		psCmd := &cobra.Command{
			Use:     "ps",
			GroupID: "filesystem",
			Short:   "Process list of selected agent",
			Run:     ps,
		}
		rootCmd.AddCommand(psCmd)

		netHelperCmd := &cobra.Command{
			Use:     "net_helper",
			GroupID: "network",
			Short:   "Network helper: ip addr, ip route, ip neigh",
			Run:     net_helper,
		}
		rootCmd.AddCommand(netHelperCmd)

		killCmd := &cobra.Command{
			Use:     "kill",
			GroupID: "util",
			Short:   "Terminate a process on selected agent",
			Example: "kill --pid 1234",
			Run:     kill,
		}
		killCmd.Flags().IntP("pid", "p", 0, "Process ID")
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

		putCmd := &cobra.Command{
			Use:     "put",
			GroupID: "filesystem",
			Short:   "Upload a file to selected agent",
			Example: "put --src /tmp/1.txt --dst /tmp/2.txt",
			Run:     UploadToAgent,
		}
		putCmd.Flags().StringP("src", "s", "", "Source file")
		putCmd.Flags().StringP("dst", "d", "", "Destination file")
		rootCmd.AddCommand(putCmd)

		screenshotCmd := &cobra.Command{
			Use:     "screenshot",
			GroupID: "util",
			Short:   "Take a screenshot of selected agent",
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
			Short:   "Kill agent process, delete agent root directory",
			Run:     suicide,
		}
		rootCmd.AddCommand(lsModCmd)

		lsTargetCmd := &cobra.Command{
			Use:     "ls_targets",
			GroupID: "agent",
			Short:   "List connected agents",
			Run:     ls_targets,
		}
		rootCmd.AddCommand(lsTargetCmd)

		searchCmd := &cobra.Command{
			Use:     "search",
			GroupID: "module",
			Short:   "Search for a module",
			Example: "search shell",
			Run:     ModuleSearch,
		}
		searchCmd.Flags().StringP("keyword", "q", "", "Keyword to search")
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

		labelAgentCmd := &cobra.Command{
			Use:     "lable",
			GroupID: "agent",
			Short:   "Label an agent with custom name",
			Example: "label --id <agent_id> --label <custom_name>",
			Run:     setTargetLabel,
		}
		labelAgentCmd.Flags().StringP("id", "", "0", "Agent ID")
		labelAgentCmd.Flags().StringP("label", "", "no-label", "Custom name")
		rootCmd.AddCommand(labelAgentCmd)

		return rootCmd
	}
}

func exitEmp3r0r(_ *console.Console) {
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
	mod, err := cmd.Flags().GetString("module")
	if err != nil {
		CliPrintError("Error getting module name: %v", err)
		return
	}
	help := make(map[string]string)
	if mod == "" {
		CliPrintError("No module specified")
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
			CliPrint("\n%s", modObj.Comment)
			CliPrettyPrint("Option", "Help", &help)
			return
		}
	}
	CliPrintError("Help yourself")
}
