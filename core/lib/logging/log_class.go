//go:build !release

package logging

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// classMu serializes class writes because tool calls and their hooks can run
// concurrently, while Logger.Printf writes straight to the shared writer.
var classMu sync.Mutex

// Class selects the tag and color for one log line. Call sites use the class
// that describes the content instead of hand-writing an ad-hoc prefix, so the
// detection loop log is consistent and greppable.
type Class int

const (
	ClassLine Class = iota
	ClassThinking
	ClassModel
	ClassTool
	ClassToolResult
	ClassBuild
	ClassCycle
	ClassEdit
	ClassAnswer
	ClassReport
	ClassWarning
	ClassError
)

func (c Class) tag() string {
	switch c {
	case ClassThinking:
		return "thinking"
	case ClassModel:
		return "model"
	case ClassTool:
		return "tool"
	case ClassToolResult:
		return "result"
	case ClassBuild:
		return "build"
	case ClassCycle:
		return "cycle"
	case ClassEdit:
		return "edit"
	case ClassAnswer:
		return "answer"
	case ClassReport:
		return "report"
	case ClassWarning:
		return "warn"
	case ClassError:
		return "error"
	default:
		return ""
	}
}

// tagColor colorizes the bracketed tag; bodyColor colors the line body.
func (c Class) tagColor() *color.Color {
	switch c {
	case ClassThinking:
		return color.New(color.Faint)
	case ClassModel:
		return color.New(color.FgCyan)
	case ClassTool:
		return color.New(color.FgHiYellow)
	case ClassToolResult:
		return color.New(color.FgGreen)
	case ClassBuild:
		return color.New(color.FgHiBlue)
	case ClassCycle:
		return color.New(color.FgHiWhite, color.Bold)
	case ClassEdit:
		return color.New(color.FgHiCyan)
	case ClassAnswer:
		return color.New(color.FgHiGreen, color.Bold)
	case ClassReport:
		return color.New(color.FgHiWhite, color.Bold)
	case ClassWarning:
		return color.New(color.FgHiYellow, color.Bold)
	case ClassError:
		return color.New(color.FgHiRed, color.Bold)
	default:
		return nil
	}
}

func (c Class) bodyColor() *color.Color {
	switch c {
	case ClassThinking:
		// Thinking dominates the log; keep it readable but visually quiet.
		return color.New(color.Faint)
	case ClassError:
		return color.New(color.FgHiRed)
	default:
		return nil
	}
}

// Classf writes one tagged line per input line to the logger output. It keeps
// the loop log readable when a model answer or build log spans many lines: the
// timestamp and tag repeat on every line instead of only the first one.
func classPrefix(class Class) string {
	prefix := time.Now().UTC().Format("15:04:05")
	tag := class.tag()
	if tag == "" {
		return prefix
	}
	if c := class.tagColor(); c != nil {
		return prefix + " " + c.Sprint("["+tag+"]")
	}
	return prefix + " [" + tag + "]"
}

func Classf(class Class, format string, a ...any) {
	text := sanitize.SanitizeText(fmt.Sprintf(format, sanitizeLogArgs(a)...))
	classMu.Lock()
	defer classMu.Unlock()
	if class == ClassReport {
		// The renderer emits SGR styling itself; sanitising it would strip the
		// styling, and per-line prefixes would break headings and tables. Keep
		// only SGR so a model-supplied link or title sequence cannot reach the
		// terminal.
		logger.Printf(nil, "%s\n%s\n", classPrefix(class), safeTerminalText(RenderMarkdown(text, 0)))
		return
	}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		lines = []string{""}
	}
	prefix := classPrefix(class)
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if c := class.bodyColor(); c != nil && line != "" {
			line = c.Sprint(line)
		}
		logger.Printf(nil, "%s %s\n", prefix, line)
	}
}

// safeTerminalText removes terminal control sequences except SGR (color and
// style), which the Markdown renderer emits for the report. OSC title/link
// sequences, cursor control, and C0/C1 controls are dropped.
func safeTerminalText(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); {
		if text[i] != 0x1b {
			r, size := utf8.DecodeRuneInString(text[i:])
			if r == utf8.RuneError && size == 1 {
				i++
				continue
			}
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				i += size
				continue
			}
			b.WriteRune(r)
			i += size
			continue
		}
		if i+1 >= len(text) {
			break
		}
		switch text[i+1] {
		case '[': // CSI: keep only SGR (final 'm')
			j := i + 2
			for j < len(text) && !(text[j] >= 0x40 && text[j] <= 0x7e) {
				j++
			}
			if j >= len(text) {
				return b.String()
			}
			if text[j] == 'm' && isSGRParams(text[i+2:j]) {
				b.WriteString(text[i : j+1])
			}
			i = j + 1
		case ']': // OSC: skip to BEL or ST
			j := i + 2
			for j < len(text) {
				if text[j] == 0x07 {
					j++
					break
				}
				if text[j] == 0x1b && j+1 < len(text) && text[j+1] == '\\' {
					j += 2
					break
				}
				j++
			}
			i = j
		default: // two-byte or lone ESC
			i += 2
		}
	}
	return b.String()
}

func isSGRParams(params string) bool {
	for i := range len(params) {
		c := params[i]
		if (c < '0' || c > '9') && c != ';' && c != ':' {
			return false
		}
	}
	return true
}

// EnableColor forces ANSI output even when the destination is not a TTY, so a
// log file tailed in a terminal keeps its colors. NO_COLOR and TERM=dumb win.
func EnableColor() {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		color.NoColor = true
		return
	}
	color.NoColor = false
}
