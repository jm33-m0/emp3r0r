package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// Prompt user for input
func Prompt(prompt string) string {
	safePrompt := sanitize.SanitizeOneLine(prompt)
	fmt.Print(color.HiCyanString("%s: ", safePrompt))
	answer := new(string)
	_, err := fmt.Scanln(answer)
	if err != nil {
		return ""
	}
	return *answer
}
