package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// TestSocks5PivotBindsLoopback verifies the pivot is reachable on the C2 host's
// loopback even when no explicit bind address is requested and the WireGuard
// address is not a host interface. Without this, local-mode operators and
// host-side tools could never reach the pivot.
func TestSocks5PivotBindsLoopback(t *testing.T) {
	origWGServerIP := wireguard.WgServerIP
	wireguard.WgServerIP = "10.255.255.1" // deliberately not a host address
	t.Cleanup(func() { wireguard.WgServerIP = origWGServerIP })

	agent := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "socks-loopback-agent"}
	_, ccPipe := net.Pipe()
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: &live.AgentControl{Index: 0, Conn: ccPipe}})
	t.Cleanup(func() {
		live.ForgetAgent(agent.UUID)
		_ = ccPipe.Close()
	})

	port := freeTCPPort(t)
	if err := StartSocks5Proxy(agent.Tag, port, ""); err != nil {
		t.Fatalf("StartSocks5Proxy with default bind: %v", err)
	}
	t.Cleanup(func() { _ = StopSocks5Proxy(port, "") })

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("pivot is not reachable on loopback: %v", err)
	}
	_ = conn.Close()
}
