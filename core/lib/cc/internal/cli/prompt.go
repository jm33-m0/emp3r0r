package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Ask a yes/no question
func YesNo(prompt string) bool {
	fmt.Print(color.HiMagentaString("%s? [y/N]: ", prompt))
	answer := ""
	_, err := fmt.Scanln(answer)
	if err != nil {
		return false
	}
	return strings.ToLower(answer) == "y"
}

// Prompt user for input
func Prompt(prompt string) string {
	fmt.Print(color.HiCyanString("%s: ", prompt))
	answer := new(string)
	_, err := fmt.Scanln(answer)
	if err != nil {
		return ""
	}
	return *answer
}
