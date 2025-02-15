package cli

import "github.com/reeflective/console"

var Console *console.Console

func init() {
	Console = console.New("emp3r0r")
	Console.NewlineBefore = true
	Console.NewlineAfter = true
	Console.NewlineWhenEmpty = true
}
