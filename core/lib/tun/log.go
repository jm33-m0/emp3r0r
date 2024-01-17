package tun

import (
	"log"

	"github.com/fatih/color"
)

// LogFatalError print log in red, and exit
func LogFatalError(format string, a ...interface{}) {
	errorColor := color.New(color.Bold, color.FgHiRed)
	log.Fatal(errorColor.Sprintf(format, a...))
}

// LogInfo print log in blue
func LogInfo(format string, a ...interface{}) {
	infoColor := color.New(color.FgHiBlue)
	log.Print(infoColor.Sprintf(format, a...))
}

// LogWarn print log in yellow
func LogWarn(format string, a ...interface{}) {
	infoColor := color.New(color.FgHiYellow)
	log.Print(infoColor.Sprintf(format, a...))
}

// LogError print log in red, and exit
func LogError(format string, a ...interface{}) {
	errorColor := color.New(color.Bold, color.FgHiRed)
	log.Printf(errorColor.Sprintf(format, a...))
}
