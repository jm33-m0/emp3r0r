package cli

import (
	"fmt"

	"github.com/fatih/color"
)

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
