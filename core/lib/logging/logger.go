package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

type Logger struct {
	Level   int
	logChan chan string
	writer  io.Writer
}

var (
	TmuxPersistence = false // whether to keep tmux session alive after emp3r0r exits
	Level           = 2     // the global log level
)

// NewLogger creates a new logger with log level, by default it writes to stderr, if logFilePath is not empty, it will write to log file instead
func NewLogger(logFilePath string, level int) (*Logger, error) {
	writer := io.MultiWriter(os.Stderr)
	if logFilePath != "" {
		if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
			err = os.MkdirAll(filepath.Dir(logFilePath), 0755)
			if err != nil {
				return nil, err
			}
		}
		// open log file
		logf, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("error opening file: %v", err)
		}
		writer = io.MultiWriter(logf)
	}

	logger := &Logger{
		Level:  level,
		writer: writer,
	}
	logger.SetDebugLevel(level)
	logger.logChan = make(chan string, 4096)

	return logger, nil
}

// AddWriter adds a new writer to logger, for example os.Stdout
func (l *Logger) AddWriter(w io.Writer) {
	l.writer = io.MultiWriter(l.writer, w)
}

// Start starts the logger and listens for log messages, then print them to console and log file
func (l *Logger) Start() {
	log.SetOutput(l.writer)
	for {
		msg := fmt.Sprintf("%s\n", <-l.logChan)

		// log to console and file
		log.Print(msg)
		time.Sleep(10 * time.Millisecond)
	}
}

func (l *Logger) helper(format string, a []interface{}, msgColor *color.Color, _ string, _ bool) {
	logMsg := fmt.Sprintf(format, a...)
	if msgColor != nil {
		logMsg = msgColor.Sprintf(format, a...)
	}
	l.logChan <- logMsg
}

func (l *Logger) Debug(format string, a ...interface{}) {
	if l.Level >= 3 {
		l.helper(format, a, nil, "DEBUG", false)
	}
}

func (l *Logger) Info(format string, a ...interface{}) {
	if l.Level >= 2 {
		l.helper(format, a, nil, "INFO", false)
	}
}

func (l *Logger) Warning(format string, a ...interface{}) {
	if l.Level >= 1 {
		l.helper(format, a, color.New(color.FgHiYellow), "WARN", false)
	}
}

// Msg prints a message to console and log file, regardless of log level
func (logger *Logger) Msg(format string, a ...interface{}) {
	logger.helper(format, a, nil, "MSG", false)
}

// Alert prints an alert message with custom color in bold font to console and log file, regardless of log level
func (l *Logger) Alert(textColor color.Attribute, format string, a ...interface{}) {
	l.helper(format, a, color.New(textColor, color.Bold), "ALERT", false)
}

// Success prints a success message in green and bold font to console and log file, regardless of log level
func (l *Logger) Success(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiGreen, color.Bold), "SUCCESS", true)
}

// Fatal prints a fatal error message in red, bold and italic font to console and log file, then exits the program
func (l *Logger) Fatal(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), "FATAL", true)
	l.Msg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	time.Sleep(2 * time.Second) // give user some time to read the error message
	log.Fatal(color.New(color.Bold, color.FgHiRed).Sprintf(format, a...))
}

// Error prints an error message in red and bold font to console and log file, regardless of log level
func (l *Logger) Error(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold), "ERROR", true)
}

func (l *Logger) SetDebugLevel(level int) {
	l.Level = level
	Level = level
	if level > 2 {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lmsgprefix)
	} else {
		log.SetFlags(log.Ldate | log.Ltime | log.LstdFlags)
	}
}
