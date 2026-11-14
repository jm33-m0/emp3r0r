//go:build release

package logging

// Class selects the tag and color for one log line. Release builds keep the
// symbol so C2-side packages still compile, but the loop logger is disabled
// with the rest of the operator logging.
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

func Classf(Class, string, ...any) {}

// RenderMarkdown is disabled with the rest of the operator logger in release
// builds; callers receive the original text.
func RenderMarkdown(text string, _ int) string { return text }

func EnableColor() {}
