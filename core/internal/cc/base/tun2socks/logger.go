package tun2socks

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// singLogger adapts sing's logger interface to emp3r0r's logger.
type singLogger struct {
	tag string
}

func (l *singLogger) prefix() string { return "sing-tun[" + l.tag + "]" }

func (l *singLogger) Trace(args ...any) { logging.Debugf("%s: %s", l.prefix(), fmt.Sprint(args...)) }

func (l *singLogger) Debug(args ...any) { logging.Debugf("%s: %s", l.prefix(), fmt.Sprint(args...)) }
func (l *singLogger) Info(args ...any)  { logging.Infof("%s: %s", l.prefix(), fmt.Sprint(args...)) }
func (l *singLogger) Warn(args ...any)  { logging.Warningf("%s: %s", l.prefix(), fmt.Sprint(args...)) }

func (l *singLogger) Error(args ...any) { logging.Errorf("%s: %s", l.prefix(), fmt.Sprint(args...)) }

func (l *singLogger) Fatal(args ...any) {
	logging.Errorf("%s: FATAL %s", l.prefix(), fmt.Sprint(args...))
}

func (l *singLogger) Panic(args ...any) {
	logging.Errorf("%s: PANIC %s", l.prefix(), fmt.Sprint(args...))
}
