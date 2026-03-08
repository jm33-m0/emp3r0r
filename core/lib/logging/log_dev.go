//go:build !release
// +build !release

package logging

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var logger *Logger

func Print(a ...any) {
	logger.Msg("%v", fmt.Sprint(a...))
}

func Println(a ...any) {
	logger.Msg("%v", fmt.Sprint(a...))
}

func Printf(format string, a ...any) {
	logger.Msg(format, a...)
}

func RawPrintf(textColor *color.Color, format string, a ...any) {
	logger.Printf(textColor, format, a...)
}

func Writer() io.Writer {
	return logger.writer
}

func Sprintf(format string, a ...any) string {
	return fmt.Sprintf(format, a...)
}

func Successf(format string, a ...any) {
	logger.Success(format, a...)
}

func Infof(format string, a ...any) {
	logger.Info(format, a...)
}

func Debugf(format string, a ...any) {
	logger.Debug(format, a...)
}

func Warningf(format string, a ...any) {
	logger.Warning(format, a...)
}

func Errorf(format string, a ...any) {
	logger.Error(format, a...)
}

func Fatalf(format string, a ...any) {
	logger.Fatal(format, a...)
}

func Fatal(a ...any) {
	logger.Msg("%v", fmt.Sprint(a...))
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
	logger.SetOutput(w)
	logger.Start()
}

// AddWriter add a new writer to logging package, for example os.Stdout
func AddWriter(w io.Writer) {
	logger.AddWriter(w)
	logger.Start()
}

// initialize logger
func init() {
	var err error
	logger, err = NewLogger("", 2)
	if err != nil {
		panic(err)
	}
	logger.Start()
}
