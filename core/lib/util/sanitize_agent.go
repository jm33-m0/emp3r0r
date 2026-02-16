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
	a.ShortID = SanitizeOneLine(a.ShortID)
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

	// AgentProcess
	if a.Process != nil {
		a.Process.Cmdline = SanitizeOneLine(a.Process.Cmdline)
		a.Process.Parent = SanitizeOneLine(a.Process.Parent)
	}
}

// SanitizeMsgTunMetadata sanitizes agent-identifying metadata in message tunnel data.
// Command output (Response) must be sanitized at presentation time depending on context.
func SanitizeMsgTunMetadata(m *def.MsgTunData) {
	if m == nil {
		return
	}
	m.Tag = SanitizeOneLine(m.Tag)
	m.AgentUUID = SanitizeOneLine(m.AgentUUID)
	m.AgentUUIDSig = SanitizeOneLine(m.AgentUUIDSig)
}
