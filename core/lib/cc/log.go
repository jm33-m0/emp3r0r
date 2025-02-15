//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

var Logger *logging.Logger

func LogDebug(format string, a ...interface{}) {
	Logger.Debug(format, a...)
}

func LogInfo(format string, a ...interface{}) {
	Logger.Info(format, a...)
}

func LogWarning(format string, a ...interface{}) {
	Logger.Warning(format, a...)
}

func LogMsg(format string, a ...interface{}) {
	Logger.Msg(format, a...)
}

func LogAlert(textColor color.Attribute, format string, a ...interface{}) {
	Logger.Alert(textColor, format, a...)
}

func LogSuccess(format string, a ...interface{}) {
	Logger.Success(format, a...)
}

func LogFatal(format string, a ...interface{}) {
	Logger.Fatal(format, a...)
}

func LogError(format string, a ...interface{}) {
	Logger.Error(format, a...)
}

func setDebugLevel(cmd *cobra.Command, args []string) {
	level, err := cmd.Flags().GetInt("level")
	if err != nil {
		LogError("Invalid debug level: %v", err)
		return
	}
	if level > 4 || level < 0 {
		LogError("Invalid debug level: %d", level)
		return
	}
	Logger.SetDebugLevel(level)
}

// SetupLoggers set up logger with log file and agent response pane
func SetupLoggers(logfile string) (err error) {
	// set up logger with log file
	Logger, err = logging.NewLogger(logfile, 2)
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}

	for OutputPane == nil {
		// wait for OutputPane to be initialized
		util.TakeABlink()
	}

	// Redirect logs to agent response pane
	agent_resp_pane_tty, err := os.OpenFile(OutputPane.TTY, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("logger failed to open agent response pane: %v", err)
	}
	Logger.AddWriter(agent_resp_pane_tty)

	// set up logger for multiple packages and unify log output
	tun.Logger = Logger
	util.Logger = Logger

	// Start logger
	Logger.Start()

	// shouldn't reach here
	return fmt.Errorf("logger exited")
}
