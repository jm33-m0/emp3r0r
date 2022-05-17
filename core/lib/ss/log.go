package ss

import (
	"log"

	"github.com/fatih/color"
)

func logf(f string, v ...interface{}) {
	if ServerConfig.Verbose {
		log.Printf(color.YellowString("Shadowsocks server: ")+f, v...)
	}
}

type logHelper struct {
	prefix string
}

func (l *logHelper) Write(p []byte) (n int, err error) {
	if ServerConfig.Verbose {
		log.Printf("%s%s\n", l.prefix, p)
		return len(p), nil
	}
	return len(p), nil
}

func newLogHelper(prefix string) *logHelper {
	return &logHelper{prefix}
}
