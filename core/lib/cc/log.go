//go:build linux
// +build linux

package cc

import (
	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

var Logger = logging.NewLogger(2)

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
	Logger.SetDebugLevel(level)
}
