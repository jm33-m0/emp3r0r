package tun

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var Logger = logging.NewLogger(2)

// LogFatalError print log in red, and exit
func LogFatalError(format string, a ...interface{}) {
	Logger.Fatal(format, a...)
}

// LogInfo print log in blue
func LogInfo(format string, a ...interface{}) {
	Logger.Info(format, a...)
}

// LogWarn print log in yellow
func LogWarn(format string, a ...interface{}) {
	Logger.Warning(format, a...)
}

// LogError print log in red, and exit
func LogError(format string, a ...interface{}) {
	Logger.Error(format, a...)
}
