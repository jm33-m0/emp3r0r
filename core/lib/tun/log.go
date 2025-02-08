package tun

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var Logger = logging.NewLogger(2)

// LogFatalError print error, and exit
func LogFatalError(format string, a ...interface{}) {
	Logger.Fatal(format, a...)
}

// LogInfo print normal logs
func LogInfo(format string, a ...interface{}) {
	Logger.Info(format, a...)
}

// LogDebug print least important logs
func LogDebug(format string, a ...interface{}) {
	Logger.Debug(format, a...)
}

// LogWarn print warning logs
func LogWarn(format string, a ...interface{}) {
	Logger.Warning(format, a...)
}

// LogError print log errors
func LogError(format string, a ...interface{}) {
	Logger.Error(format, a...)
}
