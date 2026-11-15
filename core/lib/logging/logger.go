//go:build !release

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

type logSink struct {
	w     io.Writer
	plain bool // file sink: receive rendered text without ANSI or Markdown markers
}

type Logger struct {
	Level   int
	logChan chan string
	writer  io.Writer
	sinks   []logSink
	ctx     context.Context
	cancel  context.CancelFunc

	// BroadcastHandler is called whenever Notify is called.
	// Used to send important logs to the operator console.
	BroadcastHandler func(level, msg string)
}

var (
	TmuxPersistence = false // whether to keep tmux session alive after emp3r0r exits
	Level           = 2     // the global log level
)

// NewLogger creates a new logger with log level, by default it writes to stderr, if logFilePath is not empty, it will write to log file instead
func NewLogger(logFilePath string, level int) (*Logger, error) {
	sinks := []logSink{{w: os.Stderr}}
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
			return nil, fmt.Errorf("error opening file: %w", err)
		}
		// The file receives plain text only: the console writer in the same
		// MultiWriter keeps ANSI colors, but the on-disk log is stripped so
		// module output in it stays machine-parseable (e.g. bofhound reading
		// ldapsearch results from emp3r0r.log).
		sinks = []logSink{{w: PlainFileWriter(logf), plain: true}}
	}

	logger := &Logger{
		Level: level,
		sinks: sinks,
	}
	logger.rebuildWriter()
	logger.SetDebugLevel(level)
	logger.logChan = make(chan string, 4096)
	logger.ctx, logger.cancel = context.WithCancel(context.Background())

	return logger, nil
}

// rebuildWriter keeps the aggregate writer in sync with the typed sinks.
func (l *Logger) rebuildWriter() {
	switch len(l.sinks) {
	case 0:
		l.writer = nil
	case 1:
		l.writer = l.sinks[0].w
	default:
		writers := make([]io.Writer, 0, len(l.sinks))
		for _, sink := range l.sinks {
			writers = append(writers, sink.w)
		}
		l.writer = io.MultiWriter(writers...)
	}
}

// AddWriter adds a new terminal writer to logger, for example os.Stdout.
func (l *Logger) AddWriter(w io.Writer) {
	l.sinks = append(l.sinks, logSink{w: w})
	l.rebuildWriter()
}

// SetFileOutput makes w the plain-text file sink. It is used for the on-disk
// log; terminal sinks are added later with AddWriter.
func (l *Logger) SetFileOutput(w io.Writer) {
	l.sinks = []logSink{{w: PlainFileWriter(w), plain: true}}
	l.rebuildWriter()
}

// SetOutput set logger writer, for example os.Stdout. It replaces the sinks.
func (l *Logger) SetOutput(w io.Writer) {
	l.sinks = []logSink{{w: w}}
	l.rebuildWriter()
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
	newLogger.sinks = append([]logSink(nil), l.sinks...)
	newLogger.rebuildWriter()

	// Ensure the new logger is properly referenced
	*l = *newLogger

	// Start logging
	log.SetOutput(l)

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
func sanitizeLogArg(v any) any {
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

func sanitizeLogArgs(args []any) []any {
	if len(args) == 0 {
		return args
	}
	safe := make([]any, len(args))
	for i := range args {
		safe[i] = sanitizeLogArg(args[i])
	}
	return safe
}

func (l *Logger) helper(format string, a []any, msgColor *color.Color, _ string, _ bool) {
	safeArgs := sanitizeLogArgs(a)
	logMsg := fmt.Sprintf(format, safeArgs...)
	if msgColor != nil {
		logMsg = msgColor.Sprint(logMsg)
	}
	l.logChan <- logMsg
}

func (l *Logger) Debug(format string, a ...any) {
	if l.Level >= 3 {
		l.helper(format, a, nil, DEBUG, false)
	}
}

func (l *Logger) Info(format string, a ...any) {
	if l.Level >= 2 {
		l.helper(format, a, nil, INFO, false)
	}
}

func (l *Logger) Warning(format string, a ...any) {
	if l.Level >= 1 {
		l.helper(format, a, color.New(color.FgHiYellow), WARN, false)
	}
}

// Msg prints a message to console and log file, regardless of log level
func (logger *Logger) Msg(format string, a ...any) {
	logger.helper(format, a, nil, INFO, false)
}

// Printf writes formatted output directly to the multi-writer without log prefixes.
func (l *Logger) Printf(textColor *color.Color, format string, a ...any) {
	logMsg := fmt.Sprintf(format, a...)
	if textColor != nil {
		logMsg = textColor.Sprint(logMsg)
	}
	l.writeRaw([]byte(logMsg))
}

// Write lets the standard library logger broadcast through the typed sinks.
func (l *Logger) Write(p []byte) (int, error) {
	l.writeRaw(p)
	return len(p), nil
}

func (l *Logger) writeRaw(p []byte) {
	if len(l.sinks) == 0 {
		if l.writer != nil {
			_, _ = l.writer.Write(p)
		}
		return
	}
	for _, sink := range l.sinks {
		if sink.plain {
			if _, err := sink.w.Write(stripANSICodes(p)); err != nil {
				continue
			}
			continue
		}
		_, _ = sink.w.Write(p)
	}
}

// PrintfClass writes one class-formatted block to every sink. Terminal sinks
// receive the ANSI-rendered version; plain file sinks receive the version
// without ANSI or Markdown heading markers.
func (l *Logger) PrintfClass(terminal, plain string) {
	if len(l.sinks) == 0 {
		if l.writer != nil {
			_, _ = io.WriteString(l.writer, terminal)
		}
		return
	}
	for _, sink := range l.sinks {
		if sink.plain {
			_, _ = sink.w.Write(stripANSICodes([]byte(plain)))
			continue
		}
		_, _ = io.WriteString(sink.w, terminal)
	}
}

// Success prints a success message in green and bold font to console and log file, regardless of log level
func (l *Logger) Success(format string, a ...any) {
	l.helper(format, a, color.New(color.FgHiGreen, color.Bold), SUCCESS, true)
}

// Fatal prints a fatal error message in red, bold and italic font to console and log file, then exits the program.
func (l *Logger) Fatal(format string, a ...any) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold, color.Italic), FATAL, true)
	l.Msg("Run 'tmux kill-session -t emp3r0r' to clean up dead emp3r0r windows")
	time.Sleep(2 * time.Second) // give user some time to read the error message
	os.Exit(1)
}

// Error prints an error message in red and bold font to console and log file, regardless of log level
func (l *Logger) Error(format string, a ...any) {
	l.helper(format, a, color.New(color.FgHiRed, color.Bold), ERROR, true)
}

// Notify prints a message and also triggers the broadcast handler (if set).
// Used for logs that are important enough to be shown to the operator.
func (l *Logger) Notify(level, format string, a ...any) {
	// Log locally first
	switch level {
	case SUCCESS:
		l.Success(format, a...)
	case INFO:
		l.Info(format, a...)
	case WARN:
		l.Warning(format, a...)
	case ERROR:
		l.Error(format, a...)
	default:
		l.helper(format, a, nil, level, false)
	}

	// Trigger broadcast
	if l.BroadcastHandler != nil {
		safeArgs := sanitizeLogArgs(a)
		msg := fmt.Sprintf(format, safeArgs...)
		l.BroadcastHandler(level, msg)
	}
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
