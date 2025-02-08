package util

import "github.com/jm33-m0/emp3r0r/core/lib/logging"

var Logger = logging.NewLogger(2)

func LogDebug(format string, args ...interface{}) {
	Logger.Debug(format, args...)
}

func LogError(format string, args ...interface{}) {
	Logger.Error(format, args...)
}
