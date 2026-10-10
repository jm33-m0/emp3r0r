package server

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestAgentConnectedNoticeIncludesUsefulFields(t *testing.T) {
	a := &def.Emp3r0rAgent{
		Tag:            "1a2b3c4d",
		Name:           `host\user`,
		OS:             "Ubuntu 22.04.3 LTS (x86_64)",
		Kernel:         "5.15.0-91-generic",
		Arch:           "x86_64",
		GOOS:           "linux",
		GOArch:         "amd64",
		Hostname:       "host.example.com",
		User:           "user (/home/user), uid=1000, gid=1000",
		HasRoot:        true,
		IPs:            []string{"10.0.0.1", "10.0.0.2"},
		From:           "203.0.113.7:51422",
		Transport:      "HTTP2",
		MeshRoute:      "gateway",
		P2PTransport:   "kcp",
		P2PRelayPort:   "4000",
		MeshGossipPort: "4001",
		Process:        &def.AgentProcess{Cmdline: "/usr/bin/x", PID: 1234, PPID: 1, Parent: "systemd"},
		Uptime:         "3d 4h 5m",
		Version:        "9.9.9-agent-version",
	}

	notice := agentConnectedNotice(a)

	for _, want := range []string{
		"1a2b3c4d",
		"Ubuntu 22.04.3 LTS",
		"5.15.0-91-generic",
		"host.example.com",
		"uid=1000",
		"root",
		"10.0.0.1, 10.0.0.2",
		"203.0.113.7:51422",
		"HTTP2",
		"gateway — kcp 4000 4001",
		"/usr/bin/x",
		"pid=1234",
		"systemd",
		"3d 4h 5m",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice missing %q:\n%s", want, notice)
		}
	}

	// The agent must not advertise a hardcoded build version of itself.
	if strings.Contains(notice, "9.9.9-agent-version") || strings.Contains(notice, "Version:") {
		t.Errorf("notice leaked the agent build version:\n%s", notice)
	}
}

func TestAgentConnectedNoticeSkipsEmptyAndNA(t *testing.T) {
	a := &def.Emp3r0rAgent{
		Tag:       "aabbccdd",
		OS:        "N/A",
		CPU:       "N/A",
		Hardware:  "",
		IPs:       nil,
		MeshRoute: "direct",
	}

	notice := agentConnectedNotice(a)
	if !strings.Contains(notice, "aabbccdd") {
		t.Fatalf("notice lost the ID:\n%s", notice)
	}
	if strings.Contains(notice, "N/A") {
		t.Errorf("notice should omit N/A fields:\n%s", notice)
	}
	if strings.Contains(notice, "P2P:") {
		t.Errorf("direct (non-P2P) route should not produce a P2P line:\n%s", notice)
	}
}

func TestAgentConnectedNoticeSanitizesHostileFields(t *testing.T) {
	a := &def.Emp3r0rAgent{
		Tag:      "aabbccdd",
		Hostname: "evil\x1b[2Jhost\ninjected",
		User:     "\x07bell\x1b]52;c;payload\x07",
	}

	notice := agentConnectedNotice(a)
	if strings.ContainsRune(notice, 0x1b) || strings.ContainsRune(notice, 0x07) {
		t.Fatalf("notice kept terminal escapes: %q", notice)
	}
	// The hostile newline must be collapsed so the value stays on its label's
	// line instead of injecting a fake field/line.
	var hostLine, userLine string
	for _, line := range strings.Split(notice, "\n") {
		switch {
		case strings.Contains(line, "Host:"):
			hostLine = line
		case strings.Contains(line, "User:"):
			userLine = line
		}
	}
	if !strings.Contains(hostLine, "evil") || !strings.Contains(hostLine, "injected") {
		t.Fatalf("host field did not stay on one line: %q", hostLine)
	}
	if !strings.Contains(userLine, "bell") {
		t.Fatalf("user field missing: %q", userLine)
	}
}

func TestAgentConnectedNoticeNilIsSafe(t *testing.T) {
	if got := agentConnectedNotice(nil); got == "" {
		t.Fatal("nil agent produced an empty notice")
	}
}
