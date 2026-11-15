//go:build !release

package logging

import (
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/fatih/color"
	"github.com/muesli/termenv"
)

// RenderMarkdown renders Markdown as terminal text. The renderer never
// executes raw HTML and never reads local files; it only emits styled text.
// A rendering failure returns the input unchanged so a report is never lost.
func RenderMarkdown(text string, width int) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	if width <= 0 {
		width = TerminalWidth()
	}
	profile := termenv.ANSI256
	if color.NoColor {
		profile = termenv.Ascii
	}
	options := []glamour.TermRendererOption{
		glamour.WithStandardStyle("dark"),
		// The loop log is a file tailed in a terminal, so the renderer must
		// not downgrade to ASCII just because its writer is not a TTY. The
		// color budget still follows NO_COLOR / TERM=dumb via color.NoColor.
		glamour.WithColorProfile(profile),
		glamour.WithWordWrap(width),
	}
	renderer, err := glamour.NewTermRenderer(options...)
	if err != nil {
		return text
	}
	rendered, err := renderer.Render(text)
	if err != nil {
		return text
	}
	return strings.TrimRight(rendered, "\n")
}

// RenderMarkdownPlain renders Markdown for the on-disk sink: no ANSI, and no
// heading markers that only make sense in a terminal theme. Structure such as
// bullets, tables, and code blocks is preserved.
func RenderMarkdownPlain(text string, width int) string {
	rendered := string(stripANSICodes([]byte(RenderMarkdown(text, width))))
	lines := strings.Split(rendered, "\n")
	for i, line := range lines {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent > 2 {
			continue // code blocks and quoted content keep their leading markers
		}
		trimmed := line[indent:]
		level := 0
		for level < len(trimmed) && trimmed[level] == '#' {
			level++
		}
		if level == 0 || level > 6 || level >= len(trimmed) || trimmed[level] != ' ' {
			continue
		}
		lines[i] = line[:indent] + trimmed[level+1:]
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}
