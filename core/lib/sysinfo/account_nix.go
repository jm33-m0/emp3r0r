//go:build !windows
// +build !windows

package sysinfo

import (
	"bufio"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"
	"strings"
)

func crossPlatformHasRoot() bool {
	return os.Geteuid() == 0
}

// CheckAccount : check account info by parsing /etc/passwd
func CheckAccount(username string) (accountInfo map[string]string, err error) {
	// initialize accountInfo map
	accountInfo = make(map[string]string)

	// parse /etc/passwd
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		logging.Println(err)
		return nil, err
	}
	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		accountInfo["username"] = fields[0]
		if username != accountInfo["username"] {
			continue
		}
		accountInfo["home"] = fields[len(fields)-2]
		accountInfo["shell"] = fields[len(fields)-1]

	}

	return
}
