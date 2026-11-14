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
	}
	if width > 0 {
		options = append(options, glamour.WithWordWrap(width))
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
