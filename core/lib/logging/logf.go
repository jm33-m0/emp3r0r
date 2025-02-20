package logging

import (
	"io"

	"github.com/spf13/cobra"
)

var logger *Logger

func Printf(format string, a ...interface{}) {
	logger.Msg(format, a...)
}

func Successf(format string, a ...interface{}) {
	logger.Success(format, a...)
}

func Infof(format string, a ...interface{}) {
	logger.Info(format, a...)
}

func Debugf(format string, a ...interface{}) {
	logger.Debug(format, a...)
}

func Warningf(format string, a ...interface{}) {
	logger.Warning(format, a...)
}

func Errorf(format string, a ...interface{}) {
	logger.Error(format, a...)
}

func Fatalf(format string, a ...interface{}) {
	logger.Fatal(format, a...)
}

func CmdSetDebugLevel(cmd *cobra.Command, args []string) {
	level, err := cmd.Flags().GetInt("level")
	if err != nil {
		Errorf("Invalid debug level: %v", err)
		return
	}
	if level > 4 || level < 0 {
		Errorf("Invalid debug level: %d", level)
		return
	}
	logger.SetDebugLevel(level)
}

// SetOutput set a new writer to logging package, for example os.Stdout
func SetOutput(w io.Writer) {
	logger.writer = w
}

func init() {
	var err error
	logger, err = NewLogger("", 2)
	if err != nil {
		panic(err)
	}
}
