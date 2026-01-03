//go:build release
// +build release

package logging

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func Print(a ...interface{}) {
}

func Println(a ...interface{}) {
}

func Printf(format string, a ...interface{}) {
}

func Writer() io.Writer {
	return io.Discard
}

func Sprintf(format string, a ...interface{}) string {
	return fmt.Sprint(a...)
}

func Successf(format string, a ...interface{}) {
}

func Infof(format string, a ...interface{}) {
}

func Debugf(format string, a ...interface{}) {
}

func Warningf(format string, a ...interface{}) {
}

func Errorf(format string, a ...interface{}) {
}

func Fatalf(format string, a ...interface{}) {
}

func Fatal(a ...interface{}) {
}

func CmdSetDebugLevel(cmd *cobra.Command, args []string) {
}

func SetOutput(w io.Writer) {
}

func AddWriter(w io.Writer) {
}
