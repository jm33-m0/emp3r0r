//go:build release
// +build release

package logging

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func Print(a ...any) {
}

func Println(a ...any) {
}

func Printf(format string, a ...any) {
}

func RawPrintf(textColor *color.Color, format string, a ...any) {
}

func Writer() io.Writer {
	return io.Discard
}

func Sprintf(format string, a ...any) string {
	return fmt.Sprint(a...)
}

func Successf(format string, a ...any) {
}

func Infof(format string, a ...any) {
}

func Debugf(format string, a ...any) {
}

func Warningf(format string, a ...any) {
}

func Errorf(format string, a ...any) {
}

func Fatalf(format string, a ...any) {
}

func Fatal(a ...any) {
}

func CmdSetDebugLevel(cmd *cobra.Command, args []string) {
}

func SetOutput(w io.Writer) {
}

func AddWriter(w io.Writer) {
}
