//go:build release

package logging

import (
	"fmt"
	"io"
)

// The release logger is intentionally a set of no-ops: every agent payload is
// built with this file instead of the full logger, and it must not drag the
// operator's CLI/color dependencies (fatih/color, spf13/cobra) into the agent.
// Keep every exported symbol the rest of the codebase uses, but accept opaque
// types so no third-party import leaks into the agent's binary.

func Print(a ...any) {
}

func Println(a ...any) {
}

func Printf(format string, a ...any) {
}

func RawPrintf(_ any, format string, a ...any) {
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

func Notify(level, format string, a ...any) {
}

func SetBroadcastHandler(h func(level, msg string)) {
}

// SetDebugLevel is a no-op in release builds.
func SetDebugLevel(level int) {
}

func Fatal(a ...any) {
}

func CmdSetDebugLevel(_ any, _ []string) {
}

func SetOutput(w io.Writer) {
}

func AddWriter(w io.Writer) {
}
