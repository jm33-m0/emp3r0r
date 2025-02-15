package util

import (
	"log"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var Logger *logging.Logger

func init() {
	var err error
	Logger, err = logging.NewLogger("", 2)
	if err != nil {
		log.Fatalf("util init: failed to set up logger: %v", err)
	}
}

func LogDebug(format string, args ...interface{}) {
	Logger.Debug(format, args...)
}

func LogError(format string, args ...interface{}) {
	Logger.Error(format, args...)
}
