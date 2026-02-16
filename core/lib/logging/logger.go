package logging

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// Raw marks a string as trusted, pre-sanitized output.
//
// Use sparingly and only with strings constructed from trusted/static content
// or from already-sanitized components (e.g., UI color formatting).
type Raw string

const (
	SUCCESS = "SUCCESS"
	INFO    = "INFO"
	DEBUG   = "DEBUG"
	WARN    = "WARN"
	ERROR   = "ERROR"
	FATAL   = "FATAL"
)

type Logger struct {
	Level   int
	logChan chan string
	writer  io.Writer
	ctx     context.Context
	cancel  context.CancelFunc
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
			err = os.MkdirAll(filepath.Dir(logFilePath), 0o755)
			if err != nil {
				return nil, err
			}
		}
		// open log file
		logf, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
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
	logger.ctx, logger.cancel = context.WithCancel(context.Background())

	return logger, nil
}

// AddWriter adds a new writer to logger, for example os.Stdout
func (l *Logger) AddWriter(w io.Writer) {
	if l.writer == nil {
		l.writer = w
	} else {
		l.writer = io.MultiWriter(l.writer, w)
	}
}

// SetOutput set logger writer, for example os.Stdout
func (l *Logger) SetOutput(w io.Writer) {
	l.writer = w
}

// Start starts the logger, it listens for log messages and writes to the writer
func (l *Logger) Start() {
	// Cancel the previous logger if applicable
	if l.cancel != nil {
		l.cancel()
	}

	// Create a new logger
	newLogger, err := NewLogger("", 2)
	if err != nil {
		panic(err)
	}
	newLogger.SetOutput(l.writer)

	// Ensure the new logger is properly referenced
	*l = *newLogger

	// Start logging
	log.SetOutput(l.writer)

	// Listen for log messages without blocking
	go func() {
		for {
			select {
			case msg, ok := <-l.logChan:
				if !ok {
					return // Channel closed, exit goroutine
				}
				log.Print(msg)
			case <-l.ctx.Done():
				return // Stop logging when context is canceled
			}
		}
	}()
}

// sanitizeLogArg sanitizes a single log argument, with defense-in-depth approach.
// Even though data is sanitized at storage time, this provides an additional safety layer.
func sanitizeLogArg(v interface{}) interface{} {
	switch t := v.(type) {
	case nil:
		return nil
	case Raw:
		return string(t) // Raw type bypasses sanitization (trusted/pre-sanitized)
	case string:
		return sanitize.SanitizeText(t)
	case []byte:
		return sanitize.SanitizeText(string(t))
	case error:
		return sanitize.SanitizeText(t.Error())
	case fmt.Stringer:
		return sanitize.SanitizeText(t.String())
	default:
		return v
	}
}

func sanitizeLogArgs(args []interface{}) []interface{} {
	if len(args) == 0 {
		return args
	}
	safe := make([]interface{}, len(args))
	for i := range args {
		safe[i] = sanitizeLogArg(args[i])
	}
	return safe
}

func (l *Logger) helper(format string, a []interface{}, msgColor *color.Color, _ string, _ bool) {
	safeArgs := sanitizeLogArgs(a)
	logMsg := fmt.Sprintf(format, safeArgs...)
	if msgColor != nil {
		logMsg = msgColor.Sprint(logMsg)
	}
	l.logChan <- logMsg
}

func (l *Logger) Debug(format string, a ...interface{}) {
	if l.Level >= 3 {
		l.helper(format, a, nil, DEBUG, false)
	}
}

func (l *Logger) Info(format string, a ...interface{}) {
	if l.Level >= 2 {
		l.helper(format, a, nil, INFO, false)
	}
}

func (l *Logger) Warning(format string, a ...interface{}) {
	if l.Level >= 1 {
		l.helper(format, a, color.New(color.FgHiYellow), WARN, false)
	}
}

// Msg prints a message to console and log file, regardless of log level
func (logger *Logger) Msg(format string, a ...interface{}) {
	logger.helper(format, a, nil, INFO, false)
}

// Alert prints an alert message with custom color in bold font to console and log file, regardless of log level
func (l *Logger) Alert(textColor color.Attribute, format string, a ...interface{}) {
	l.helper(format, a, color.New(textColor, color.Bold), WARN, false)
}

// Success prints a success message in green and bold font to console and log file, regardless of log level
func (l *Logger) Success(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiGreen, color.Bold), SUCCESS, true)
}

// Fatal prints a fatal error message in red, bold and italic font to console and log file, then exits the program
func (l *Logger) Fatal(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), FATAL, true)
	l.Msg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	time.Sleep(2 * time.Second) // give user some time to read the error message
	safeArgs := sanitizeLogArgs(a)
	log.Fatal(color.New(color.Bold, color.FgHiRed).Sprint(fmt.Sprintf(format, safeArgs...)))
}

// Error prints an error message in red and bold font to console and log file, regardless of log level
func (l *Logger) Error(format string, a ...interface{}) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold), ERROR, true)
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
