package util

import (
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// SanitizeAgentMetadata sanitizes all agent-supplied metadata fields in-place.
//
// Use this at trust boundaries (after decode/unmarshal) so data is safe-at-rest
// before storing it in memory or rendering it in UI/logs.
func SanitizeAgentMetadata(a *def.Emp3r0rAgent) {
	if a == nil {
		return
	}

	// String fields (single-line identifiers / metadata)
	a.Tag = SanitizeOneLine(a.Tag)
	a.Name = SanitizeOneLine(a.Name)
	a.Version = SanitizeOneLine(a.Version)
	a.Transport = SanitizeOneLine(a.Transport)
	a.Hostname = SanitizeOneLine(a.Hostname)
	a.Hardware = SanitizeOneLine(a.Hardware)
	a.Container = SanitizeOneLine(a.Container)
	a.Uptime = SanitizeOneLine(a.Uptime)
	a.Groups = SanitizeOneLine(a.Groups)
	a.CPU = SanitizeOneLine(a.CPU)
	a.GPU = SanitizeOneLine(a.GPU)
	a.Mem = SanitizeOneLine(a.Mem)
	a.OS = SanitizeOneLine(a.OS)
	a.GOOS = SanitizeOneLine(a.GOOS)
	a.GOArch = SanitizeOneLine(a.GOArch)
	a.Kernel = SanitizeOneLine(a.Kernel)
	a.Arch = SanitizeOneLine(a.Arch)
	a.From = SanitizeOneLine(a.From)
	a.User = SanitizeOneLine(a.User)
	a.CWD = SanitizeOneLine(a.CWD)
	a.UUID = SanitizeOneLine(a.UUID)
	a.UUIDSig = SanitizeOneLine(a.UUIDSig)
	// PublicKey is typically PEM which is multi-line; collapsing whitespace breaks PEM parsing.
	a.PublicKey = strings.TrimSpace(SanitizeText(a.PublicKey))
	a.C2Host = SanitizeOneLine(a.C2Host)
	// Mesh / P2P metadata is rendered in the tmux agent list, so it must be
	// stripped of terminal escapes just like the rest.
	a.MeshRoute = SanitizeOneLine(a.MeshRoute)
	a.P2PRelayPort = SanitizeOneLine(a.P2PRelayPort)
	a.MeshGossipPort = SanitizeOneLine(a.MeshGossipPort)
	a.P2PTransport = SanitizeOneLine(a.P2PTransport)

	// String slices
	for i, ip := range a.IPs {
		a.IPs[i] = SanitizeOneLine(ip)
	}
	for i, entry := range a.ARP {
		a.ARP[i] = SanitizeOneLine(entry)
	}
	for i, exe := range a.Exes {
		a.Exes[i] = SanitizeOneLine(exe)
	}
	for i, file := range a.Files {
		a.Files[i] = SanitizeOneLine(file)
	}

	// AgentProcess
	if a.Process != nil {
		a.Process.Cmdline = SanitizeOneLine(a.Process.Cmdline)
		a.Process.Parent = SanitizeOneLine(a.Process.Parent)
	}

	// AgentToken is issued by the C2, but a hostile agent can still echo an
	// arbitrary value in its check-in payload; sanitize before it is stored or
	// possibly rendered.
	if a.AgentToken != nil {
		a.AgentToken.AgentID = SanitizeOneLine(a.AgentToken.AgentID)
		a.AgentToken.IP = SanitizeOneLine(a.AgentToken.IP)
		a.AgentToken.Capability = SanitizeOneLine(a.AgentToken.Capability)
	}
}

// SanitizeMsgTunMetadata sanitizes agent-identifying metadata in message tunnel data.
// Command output (Response) is NOT sanitized here as it may contain binary CBOR data.
// Response should be sanitized at presentation time when converted to string.
func SanitizeMsgTunMetadata(m *def.MsgTunData) {
	if m == nil {
		return
	}
	m.Tag = SanitizeOneLine(m.Tag)
	m.AgentUUID = SanitizeOneLine(m.AgentUUID)
	m.AgentUUIDSig = SanitizeOneLine(m.AgentUUIDSig)
	m.JobID = SanitizeOneLine(m.JobID)
	m.Time = SanitizeOneLine(m.Time)

	// Sanitize command arguments
	for i := range m.CmdSlice {
		m.CmdSlice[i] = SanitizeOneLine(m.CmdSlice[i])
	}
}
