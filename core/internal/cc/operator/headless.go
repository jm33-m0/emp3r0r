package operator

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"

	"github.com/spf13/cobra"
)

// headlessMu serializes command execution. The console commands share global
// operator state (active target, logger level, tmux, jobs) and are not written
// for concurrent callers.
var headlessMu sync.Mutex

// HeadlessCommand runs one operator console command without the interactive
// UI. The command line may start with "/" so an MCP client can present it as a
// slash command. Command output goes to the operator log; asynchronous work is
// visible through jobs and job output. Commands that would terminate the MCP
// server or manipulate its terminal are rejected.
func HeadlessCommand(ctx context.Context, line string) error {
	line = strings.TrimSpace(line)
	line = strings.TrimSpace(strings.TrimPrefix(line, "/"))
	if line == "" {
		return fmt.Errorf("command is empty")
	}
	args, err := splitCommandLine(line)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("command is empty")
	}
	switch strings.ToLower(args[0]) {
	case "exit", "quit", "q", "bye", "logout", "shutdown", "stop":
		return fmt.Errorf("%s would terminate the MCP server", args[0])
	case "reset_layout":
		return fmt.Errorf("reset_layout controls the interactive console and is unavailable over MCP")
	}

	headlessMu.Lock()
	defer headlessMu.Unlock()

	root := headlessTree()
	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}

// headlessTree builds a fresh command tree for each call. Reusing one tree
// would carry flag values from an earlier invocation into the next, and a
// fresh tree also picks up modules added since the last reload.
func headlessTree() *cobra.Command {
	root := Emp3r0rCommands(EMP3R0R_CONSOLE)()
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	for _, command := range root.Commands() {
		switch command.Name() {
		case "exit", "reset_layout":
			root.RemoveCommand(command)
		}
	}
	return root
}

// splitCommandLine splits a command line into arguments. It supports single
// and double quotes and backslash escapes outside single quotes, which covers
// the flags and paths the console commands accept.
func splitCommandLine(line string) ([]string, error) {
	args := make([]string, 0, 8)
	var word strings.Builder
	inWord := false
	var quote rune
	escaped := false

	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			word.WriteRune(r)
			inWord = true
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			// Preserve Windows paths such as C:\Windows. A backslash only
			// escapes whitespace, quotes, or another backslash.
			if i+1 < len(runes) {
				next := runes[i+1]
				if next == '\\' || next == '"' || next == '\'' || unicode.IsSpace(next) {
					escaped = true
					continue
				}
			}
			word.WriteRune(r)
			inWord = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			word.WriteRune(r)
			inWord = true
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case unicode.IsSpace(r):
			if inWord {
				args = append(args, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	if escaped {
		return nil, fmt.Errorf("command ends with a dangling escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("command has an unterminated quote")
	}
	if inWord {
		args = append(args, word.String())
	}
	return args, nil
}
