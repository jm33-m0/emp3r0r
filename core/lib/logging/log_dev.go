//go:build !release

package logging

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var logger *Logger

// DisplayMarkdown writes rendered Markdown to the console without adding a
// log prefix or a timestamp, so an executive summary stays a standalone block.
func DisplayMarkdown(text string) {
	if logger == nil || strings.TrimSpace(text) == "" {
		return
	}
	terminal := safeTerminalText(RenderMarkdown(text, 0)) + "\n"
	plain := RenderMarkdownPlain(text, 0) + "\n"
	logger.PrintfClass(terminal, plain)
}

func Print(a ...any) {
	logger.Msg("%v", fmt.Sprint(a...))
}

func Println(a ...any) {
	logger.Msg("%v", fmt.Sprint(a...))
}

func RawPrintf(textColor *color.Color, format string, a ...any) {
	logger.Printf(textColor, format, a...)
}

func Writer() io.Writer {
	if logger == nil {
		return io.Discard
	}
	return logger.writerSnapshot()
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

func Notify(level, format string, a ...any) {
	logger.Notify(level, format, a...)
}

func SetBroadcastHandler(h func(level, msg string)) {
	logger.BroadcastHandler = h
}

// SetDebugLevel sets the global log level.
func SetDebugLevel(level int) {
	logger.SetDebugLevel(level)
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

// SetFileOutput sets the plain-text on-disk sink. Terminal sinks added later
// with AddWriter receive the ANSI-rendered form.
func SetFileOutput(w io.Writer) {
	logger.SetFileOutput(w)
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
