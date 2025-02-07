//go:build linux
// +build linux

package cc

import (
	"fmt"
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/ss"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/reeflective/console"
	"github.com/spf13/cobra"
)

func cliPrintHelper(format string, a []interface{}, msgColor *color.Color, _ string, _ bool) {
	logMsg := msgColor.Sprintf(format, a...)
	AsyncLogChan <- logMsg
}

var AsyncLogChan = make(chan string, 4096)

func goRoutineLogHelper(_ *console.Console) {
	for {
		logMsg := <-AsyncLogChan
		fmt.Printf("%s\n", logMsg)

		// log to file
		logf, err := os.OpenFile(ConsoleLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Logging to file: %v", err)
		}
		fmt.Fprintf(logf, "%s\n", logMsg)
		logf.Close()
		util.TakeABlink()
	}
}

func CliPrintDebug(format string, a ...interface{}) {
	if DebugLevel >= 3 {
		cliPrintHelper(format, a, color.New(color.FgBlue, color.Italic), "DEBUG", false)
	}
}

func CliPrintInfo(format string, a ...interface{}) {
	if DebugLevel >= 2 {
		cliPrintHelper(format, a, color.New(color.FgBlue), "INFO", false)
	}
}

func CliPrintWarning(format string, a ...interface{}) {
	if DebugLevel >= 1 {
		cliPrintHelper(format, a, color.New(color.FgHiYellow), "WARN", false)
	}
}

func CliPrint(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiCyan), "PRINT", false)
}

func CliMsg(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiCyan), "MSG", false)
}

func CliAlert(textColor color.Attribute, format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(textColor, color.Bold), "ALERT", false)
}

func CliPrintSuccess(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiGreen, color.Bold), "SUCCESS", true)
}

func CliFatalError(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), "ERROR", true)
	CliMsg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	log.Fatal(color.New(color.Bold, color.FgHiRed).Sprintf(format, a...))
}

func CliPrintError(format string, a ...interface{}) {
	cliPrintHelper(format, a, color.New(color.FgHiRed, color.Bold), "ERROR", true)
}

func setDebugLevel(cmd *cobra.Command, args []string) {
	level, err := cmd.Flags().GetInt("level")
	if err != nil {
		CliPrintError("Invalid debug level: %v", err)
		return
	}
	DebugLevel = level
	if DebugLevel > 2 {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lmsgprefix)
		ss.ServerConfig.Verbose = true
	} else {
		log.SetFlags(log.Ldate | log.Ltime | log.LstdFlags)
	}
}
