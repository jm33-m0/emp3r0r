package util

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// hostileMetadata returns a value that mixes printable text with terminal
// escape sequences an agent could use to attack the operator's tmux UI
// (OSC 52 clipboard write, CSI cursor control) and control characters.
func hostileMetadata(canary string) string {
	return "\x1b]52;c;ZXZpbA==\x07\x1b[2J" + canary + "\n\t\r"
}

func assertClean(t *testing.T, field, value string) {
	t.Helper()
	if strings.ContainsAny(value, "\x1b\n\r\t") {
		t.Errorf("%s still contains control/escape bytes: %q", field, value)
	}
	if !strings.Contains(value, "canary") {
		t.Errorf("%s lost its printable content: %q", field, value)
	}
}

func TestSanitizeAgentMetadataStripsTmuxHostileFields(t *testing.T) {
	hostile := hostileMetadata("canary")
	a := &def.Emp3r0rAgent{
		Tag:            hostile,
		Name:           hostile,
		Version:        hostile,
		Transport:      hostile,
		Hostname:       hostile,
		Hardware:       hostile,
		Container:      hostile,
		Uptime:         hostile,
		Groups:         hostile,
		CPU:            hostile,
		GPU:            hostile,
		Mem:            hostile,
		OS:             hostile,
		GOOS:           hostile,
		GOArch:         hostile,
		Kernel:         hostile,
		Arch:           hostile,
		From:           hostile,
		User:           hostile,
		CWD:            hostile,
		UUID:           hostile,
		UUIDSig:        hostile,
		C2Host:         hostile,
		MeshRoute:      hostile,
		P2PRelayPort:   hostile,
		MeshGossipPort: hostile,
		P2PTransport:   hostile,
		IPs:            []string{hostile},
		ARP:            []string{hostile},
		Exes:           []string{hostile},
		Files:          []string{hostile},
		Process:        &def.AgentProcess{Cmdline: hostile, Parent: hostile},
		AgentToken:     &def.AgentToken{AgentID: hostile, IP: hostile, Capability: hostile},
	}

	SanitizeAgentMetadata(a)

	fields := map[string]string{
		"Tag":                   a.Tag,
		"Name":                  a.Name,
		"Version":               a.Version,
		"Transport":             a.Transport,
		"Hostname":              a.Hostname,
		"Hardware":              a.Hardware,
		"Container":             a.Container,
		"Uptime":                a.Uptime,
		"Groups":                a.Groups,
		"CPU":                   a.CPU,
		"GPU":                   a.GPU,
		"Mem":                   a.Mem,
		"OS":                    a.OS,
		"GOOS":                  a.GOOS,
		"GOArch":                a.GOArch,
		"Kernel":                a.Kernel,
		"Arch":                  a.Arch,
		"From":                  a.From,
		"User":                  a.User,
		"CWD":                   a.CWD,
		"UUID":                  a.UUID,
		"UUIDSig":               a.UUIDSig,
		"C2Host":                a.C2Host,
		"MeshRoute":             a.MeshRoute,
		"P2PRelayPort":          a.P2PRelayPort,
		"MeshGossipPort":        a.MeshGossipPort,
		"P2PTransport":          a.P2PTransport,
		"IPs[0]":                a.IPs[0],
		"ARP[0]":                a.ARP[0],
		"Exes[0]":               a.Exes[0],
		"Files[0]":              a.Files[0],
		"Process.Cmdline":       a.Process.Cmdline,
		"Process.Parent":        a.Process.Parent,
		"AgentToken.AgentID":    a.AgentToken.AgentID,
		"AgentToken.IP":         a.AgentToken.IP,
		"AgentToken.Capability": a.AgentToken.Capability,
	}
	for name, value := range fields {
		assertClean(t, name, value)
	}
}

func TestSanitizeAgentMetadataNilIsSafe(t *testing.T) {
	SanitizeAgentMetadata(nil) // must not panic
}

func TestSanitizeMsgTunMetadataStripsHostileFields(t *testing.T) {
	hostile := hostileMetadata("canary")
	m := &def.MsgTunData{
		Tag:          hostile,
		AgentUUID:    hostile,
		AgentUUIDSig: hostile,
		JobID:        hostile,
		Time:         hostile,
		CmdSlice:     []string{hostile, "ls", hostile},
	}

	SanitizeMsgTunMetadata(m)

	for name, value := range map[string]string{
		"Tag":          m.Tag,
		"AgentUUID":    m.AgentUUID,
		"AgentUUIDSig": m.AgentUUIDSig,
		"JobID":        m.JobID,
		"Time":         m.Time,
		"CmdSlice[0]":  m.CmdSlice[0],
		"CmdSlice[2]":  m.CmdSlice[2],
	} {
		assertClean(t, name, value)
	}
	if m.CmdSlice[1] != "ls" {
		t.Errorf("clean command argument was altered: %q", m.CmdSlice[1])
	}
}
