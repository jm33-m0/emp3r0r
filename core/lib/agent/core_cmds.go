package agent

import "github.com/spf13/cobra"

func AgentCommands() *cobra.Command {
	rootCmd := &cobra.Command{
		Short: "emp3r0r agent",
	}
	// Define groups sorted by name
	rootCmd.AddGroup(
		&cobra.Group{ID: "agent", Title: "Agent Commands"},
		&cobra.Group{ID: "filesystem", Title: "File System Commands"},
		&cobra.Group{ID: "file_transfer", Title: "File Transfer Commands"},
		&cobra.Group{ID: "network", Title: "Network Commands"},
		&cobra.Group{ID: "process", Title: "Process Commands"},
	)

	// Filesystem commands
	lsCmd := &cobra.Command{
		Use:     "ls",
		Short:   "List files in a directory",
		Run:     lsCmdRun,
		GroupID: "filesystem",
	}
	lsCmd.Flags().StringP("dst", "d", ".", "Directory to list files")
	rootCmd.AddCommand(lsCmd)

	catCmd := &cobra.Command{
		Use:     "cat",
		Short:   "Read file content",
		Run:     catCmdRun,
		GroupID: "filesystem",
	}
	catCmd.Flags().StringP("dst", "d", "", "File to read")
	rootCmd.AddCommand(catCmd)

	rmCmd := &cobra.Command{
		Use:     "rm",
		Short:   "Remove file or directory",
		Run:     rmCmdRun,
		GroupID: "filesystem",
	}
	rmCmd.Flags().StringP("dst", "d", "", "Path to remove")
	rootCmd.AddCommand(rmCmd)

	mkdirCmd := &cobra.Command{
		Use:     "mkdir",
		Short:   "Create directory",
		Run:     mkdirCmdRun,
		GroupID: "filesystem",
	}
	mkdirCmd.Flags().StringP("dst", "d", "", "Directory to create")
	rootCmd.AddCommand(mkdirCmd)

	cpCmd := &cobra.Command{
		Use:     "cp",
		Short:   "Copy file or directory",
		Run:     cpCmdRun,
		GroupID: "filesystem",
	}
	cpCmd.Flags().StringP("src", "s", "", "Source path")
	cpCmd.Flags().StringP("dst", "d", "", "Destination path")
	rootCmd.AddCommand(cpCmd)

	mvCmd := &cobra.Command{
		Use:     "mv",
		Short:   "Move file or directory",
		Run:     mvCmdRun,
		GroupID: "filesystem",
	}
	mvCmd.Flags().StringP("src", "s", "", "Source path")
	mvCmd.Flags().StringP("dst", "d", "", "Destination path")
	rootCmd.AddCommand(mvCmd)

	cdCmd := &cobra.Command{
		Use:     "cd",
		Short:   "Change directory",
		Run:     cdCmdRun,
		GroupID: "filesystem",
	}
	cdCmd.Flags().StringP("dst", "d", "", "Target directory")
	rootCmd.AddCommand(cdCmd)

	pwdCmd := &cobra.Command{
		Use:     "pwd",
		Short:   "Print working directory",
		Run:     pwdCmdRun,
		GroupID: "filesystem",
	}
	rootCmd.AddCommand(pwdCmd)

	// Process commands
	psCmd := &cobra.Command{
		Use:     "ps",
		Short:   "List processes",
		Run:     psCmdRun,
		GroupID: "process",
	}
	psCmd.Flags().IntP("pid", "p", 0, "Process ID")
	psCmd.Flags().StringP("name", "n", "", "Process name")
	psCmd.Flags().StringP("user", "u", "", "User")
	psCmd.Flags().StringP("cmdline", "c", "", "Command line")
	rootCmd.AddCommand(psCmd)

	killCmd := &cobra.Command{
		Use:     "kill",
		Short:   "Kill process",
		Run:     killCmdRun,
		GroupID: "process",
	}
	killCmd.Flags().IntP("pid", "p", 0, "Process ID to kill")
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
	putCmd.Flags().StringP("file", "f", "", "File to upload")
	putCmd.Flags().StringP("path", "p", "", "Destination path")
	putCmd.Flags().Int64P("size", "s", 0, "Size of file")
	putCmd.Flags().StringP("checksum", "c", "", "File checksum")
	putCmd.Flags().StringP("addr", "h", "", "Download address")
	rootCmd.AddCommand(putCmd)

	// Add built-in commands
	rootCmd.AddCommand(C2AgentCommands())

	return rootCmd
}
