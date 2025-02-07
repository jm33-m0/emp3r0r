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
	Logger.Info(format, a, color.New(color.FgBlue), "INFO", false)
}

func LogWarning(format string, a ...interface{}) {
	Logger.Warning(format, a, color.New(color.FgHiYellow), "WARN", false)
}

func LogMsg(format string, a ...interface{}) {
	Logger.Msg(format, a, color.New(color.FgHiCyan), "MSG", false)
}

func LogAlert(textColor color.Attribute, format string, a ...interface{}) {
	Logger.Alert(textColor, format, a, "ALERT", false)
}

func LogSuccess(format string, a ...interface{}) {
	Logger.Success(format, a, color.New(color.FgHiGreen, color.Bold), "SUCCESS", true)
}

func LogFatal(format string, a ...interface{}) {
	Logger.Fatal(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), "ERROR", true)
}

func LogError(format string, a ...interface{}) {
	Logger.Error(format, a, color.New(color.FgHiRed, color.Bold), "ERROR", true)
}

func setDebugLevel(cmd *cobra.Command, args []string) {
	level, err := cmd.Flags().GetInt("level")
	if err != nil {
		LogError("Invalid debug level: %v", err)
		return
	}
	Logger.SetDebugLevel(level)
}
