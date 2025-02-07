//go:build linux
// +build linux

package logging

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/ss"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

type Logger struct {
	Level   int
	logChan chan string
	writer  io.Writer
}

func (l *Logger) helper(format string, a []interface{}, msgColor *color.Color, _ string, _ bool) {
	logMsg := msgColor.Sprintf(format, a...)
	l.logChan <- logMsg
}

// NewLogger creates a new logger with log level, log will be written to both stderr and file ~/.emp3r0r/emp3r0r.log
func NewLogger(level int) *Logger {
	// The log file is always located at ~/.emp3r0r/emp3r0r.log, ensure the directory exists
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("error getting user home directory: %v", err)
	}
	logFilePath := fmt.Sprintf("%s/.emp3r0r/emp3r0r.log", home)
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		os.MkdirAll(logFilePath, 0755)
	}

	// open log file
	logf, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	writer := io.MultiWriter(os.Stderr, logf)

	logger := &Logger{
		Level:  level,
		writer: writer,
	}
	logger.SetDebugLevel(level)
	logger.logChan = make(chan string, 4096)

	return logger
}

// Start starts the logger and listens for log messages, then print them to console and log file
func (l *Logger) Start() {
	for {
		logMsg := <-l.logChan
		fmt.Printf("%s\n", logMsg)

		// log to console and file
		l.writer.Write([]byte(logMsg + "\n"))
		util.TakeABlink()
	}
}

func (l *Logger) Debug(format string, a ...interface{}) {
	if l.Level >= 3 {
		l.helper(format, a, color.New(color.FgBlue, color.Italic), "DEBUG", false)
	}
}

func (l *Logger) Info(format string, a ...interface{}) {
	if l.Level >= 2 {
		l.helper(format, a, color.New(color.FgBlue), "INFO", false)
	}
}

func (l *Logger) Warning(format string, a ...interface{}) {
	if l.Level >= 1 {
		l.helper(format, a, color.New(color.FgHiYellow), "WARN", false)
	}
}

func (logger *Logger) Msg(format string, a ...interface{}) {
	logger.helper(format, a, color.New(color.FgHiCyan), "MSG", false)
}

func (l *Logger) Alert(textColor color.Attribute, format string, a ...interface{}) {
	l.helper(format, a, color.New(textColor, color.Bold), "ALERT", false)
}

func (l *Logger) Success(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiGreen, color.Bold), "SUCCESS", true)
}

func (l *Logger) Fatal(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), "ERROR", true)
	l.Msg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	log.Fatal(color.New(color.Bold, color.FgHiRed).Sprintf(format, a...))
}

func (l *Logger) Error(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold), "ERROR", true)
}

func (l *Logger) SetDebugLevel(level int) {
	l.Level = level
	if level > 2 {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lmsgprefix)
		ss.ServerConfig.Verbose = true
	} else {
		log.SetFlags(log.Ldate | log.Ltime | log.LstdFlags)
	}
}
