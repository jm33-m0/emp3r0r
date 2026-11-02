//go:build linux && cgo

package shellcode_stager

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// socks5PivotIdle is longer than the test agent's 5s poll window, so the idle
// period covers the message tunnel closing and at least one sleep cycle.
const socks5PivotIdle = 7 * time.Second

// socks5PivotPayload is large enough to span many relay frames and several
// agent read deadlines.
const socks5PivotPayload = 64 << 10

// runSocks5PivotCheck drives a real SOCKS5 CONNECT through the C2 listener and
// the `socks5` module on the C agent: the C2 dispatches the module, the agent
// dials the target and pipes the proxy stream, and the relay must survive an
// idle period that spans a masked-sleep cycle. If agent_sleep masks while the
// relay manager is alive the agent corrupts its own heap and stacks, so the
// payload comes back wrong or not at all.
// runSocks5PivotCheck returns whether the subtest actually ran (a -run filter
// may skip it), so the caller can allow for the check-ins a pivot causes.
func runSocks5PivotCheck(t *testing.T, agent *def.Emp3r0rAgent, doneChan <-chan error, agentOut *bytes.Buffer) (ran bool) {
	t.Helper()

	t.Run("socks5-pivot", func(t *testing.T) {
		ran = true
		coreDir, err := filepath.Abs(filepath.Join("..", "..", ".."))
		if err != nil {
			t.Fatalf("resolve core dir: %v", err)
		}
		// The operator console's module registry: socks_start hosts the relay
		// BOF from it for a C agent. The C2 server dispatches nothing itself.
		live.ModuleDirs = []string{filepath.Join(coreDir, "modules")}
		modules.InitModules()
		if err := modules.HostSocks5Relay(agent); err != nil {
			t.Fatalf("host the SOCKS5 relay BOF: %v\nAgent output:\n%s", err, agentOut.String())
		}

		target := startEchoServer(t)
		pivotPort := freeTCPPort(t)
		// Start the pivot while the agent is in its masked sleep: no live
		// message tunnel. socks_start must still succeed, and the CONNECT is
		// queued for the agent's next check-in instead of being refused.
		waitForAgentDormant(t, agent, doneChan)
		startPivotListener(t, agent.Tag, pivotPort, doneChan, agentOut)
		// Registered before the stop so it runs after it: the agent must get its
		// own poll profile back when the pivot ends.
		t.Cleanup(func() { waitForAgentGrace(t, agent.UUID, 12) })
		t.Cleanup(func() { _ = server.StopSocks5Proxy(pivotPort, "") })

		// The pivot temporarily shortens the agent's sleep and widens its poll
		// window (def.Socks5PivotPollInterval/Window: 15s + 10s, plus interval/2
		// of slack); the next check-in reports the tuned removal deadline.
		waitForAgentGrace(t, agent.UUID, 32)

		conn := socks5ConnectOnce(t, pivotPort, target)
		defer func() { _ = conn.Close() }()

		// Idle across the tunnel close and one sleep. The agent must not mask
		// while its relay manager runs.
		time.Sleep(socks5PivotIdle)

		payload := make([]byte, socks5PivotPayload)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("generate payload: %v", err)
		}
		if err := conn.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write through the pivot: %v\nAgent output:\n%s", err, agentOut.String())
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read through the pivot: %v\nAgent output:\n%s", err, agentOut.String())
		}
		if !bytes.Equal(payload, got) {
			t.Fatalf("pivot echoed %d bytes, %d differ", len(got), countDiff(payload, got))
		}
		t.Logf("socks5: %d bytes round-tripped through agent %s", len(got), agent.Tag)
	})
	return ran
}

// startEchoServer serves a loopback TCP echo endpoint and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for echo server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// startPivotListener starts the SOCKS5 pivot on the C2, waiting for the agent's
// message tunnel to be live: the listener refuses an agent that has never
// opened one.
func startPivotListener(t *testing.T, agentTag string, port int, doneChan <-chan error, agentOut *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := server.StartSocks5Proxy(agentTag, port, "127.0.0.1")
		if err == nil {
			return
		}
		if !strings.Contains(err.Error(), "not connected") {
			t.Fatalf("StartSocks5Proxy: %v\nAgent output:\n%s", err, agentOut.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("StartSocks5Proxy: %v\nAgent output:\n%s", err, agentOut.String())
		}
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited before the pivot started: %v.\nOutput:\n%s", werr, agentOut.String())
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// socks5Connect performs a raw SOCKS5 CONNECT through the pivot, retrying until
// the agent picks the module up: a CONNECT issued while the agent is asleep is
// refused, exactly as it would be for any other command.
func socks5Connect(t *testing.T, pivotPort int, target string, doneChan <-chan error, agentOut *bytes.Buffer) net.Conn {
	t.Helper()
	ip, port := socks5TargetAddr(t, target)

	deadline := time.Now().Add(3 * time.Minute)
	for attempt := 1; ; attempt++ {
		conn, err := dialSocks5(t, pivotPort, ip, port)
		if err == nil {
			return conn
		}
		if conn != nil {
			_ = conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("SOCKS5 CONNECT through the pivot: %v\nAgent output:\n%s", err, agentOut.String())
		}
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited during the pivot: %v.\nOutput:\n%s", werr, agentOut.String())
		default:
		}
		t.Logf("socks5 CONNECT attempt %d: %v (retrying)", attempt, err)
		time.Sleep(time.Second)
	}
}

// socks5TargetAddr parses an echo server address into an IPv4 address and port.
func socks5TargetAddr(t *testing.T, target string) (net.IP, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("parse echo address %q: %v", target, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("echo address %q is not IPv4", target)
	}
	port := 0
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse echo port %q: %v", portStr, err)
	}
	return ip.To4(), uint16(port)
}

// socks5ConnectOnce performs exactly one SOCKS5 CONNECT. A CONNECT sent while
// the agent sleeps must be queued and relayed, not refused, so a retry would
// hide the regression this check exists for.
func socks5ConnectOnce(t *testing.T, pivotPort int, target string) net.Conn {
	t.Helper()
	ip, port := socks5TargetAddr(t, target)
	conn, err := dialSocks5(t, pivotPort, ip, port)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("SOCKS5 CONNECT to a dormant agent: %v", err)
	}
	return conn
}

// waitForAgentDormant blocks until the agent has no live message tunnel, i.e.
// it is in its masked sleep between polls.
func waitForAgentDormant(t *testing.T, agent *def.Emp3r0rAgent, doneChan <-chan error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, ctrl, found := agents.RuntimeControlByUUID(agent.UUID)
		if !found || ctrl == nil || ctrl.Conn == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent never went dormant")
		}
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited while waiting for its masked sleep: %v", werr)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForAgentGrace blocks until the agent's next check-in reports want. It is
// how the pivot tuning and its restoration are observed from the C2.
func waitForAgentGrace(t *testing.T, uuid string, want int) {
	t.Helper()
	// A profile change is delivered at the next check-in and reported at the
	// one after that, so allow for a full tuned cycle plus delivery slack.
	deadline := time.Now().Add(90 * time.Second)
	for {
		if a := agents.GetAgentByUUID(uuid); a != nil && a.OfflineGrace == want {
			return
		}
		if time.Now().After(deadline) {
			got := -1
			if a := agents.GetAgentByUUID(uuid); a != nil {
				got = a.OfflineGrace
			}
			t.Fatalf("agent OfflineGrace = %d, want %d (pivot tuning not applied or not restored)", got, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// dialSocks5 opens one SOCKS5 connection to targetIP:targetPort through the
// pivot and returns it once the C2 accepted the CONNECT.
func dialSocks5(t *testing.T, pivotPort int, targetIP net.IP, targetPort uint16) (net.Conn, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pivotPort), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial pivot: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return conn, fmt.Errorf("set deadline: %w", err)
	}

	// Greeting: one method, "no authentication".
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return conn, fmt.Errorf("send greeting: %w", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return conn, fmt.Errorf("read method reply: %w", err)
	}
	if method[0] != 0x05 || method[1] != 0x00 {
		return conn, fmt.Errorf("pivot chose method 0x%02x%02x", method[0], method[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, targetIP...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], targetPort)
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		return conn, fmt.Errorf("send CONNECT: %w", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return conn, fmt.Errorf("read CONNECT reply: %w", err)
	}
	if reply[0] != 0x05 {
		return conn, fmt.Errorf("unexpected SOCKS version 0x%02x", reply[0])
	}
	if reply[1] != 0x00 {
		return conn, fmt.Errorf("CONNECT refused with reply code 0x%02x", reply[1])
	}
	// Consume BND.ADDR/BND.PORT so the stream starts at the relayed bytes.
	var addrLen int
	switch reply[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return conn, fmt.Errorf("read bound address length: %w", err)
		}
		addrLen = int(lenBuf[0])
	default:
		return conn, fmt.Errorf("unsupported bound address type 0x%02x", reply[3])
	}
	discard := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, discard); err != nil {
		return conn, fmt.Errorf("read bound address: %w", err)
	}
	// The relay is established; per-operation deadlines are the caller's.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return conn, fmt.Errorf("clear deadline: %w", err)
	}
	return conn, nil
}

// countDiff reports how many bytes differ, for a readable failure message.
func countDiff(a, b []byte) int {
	n := 0
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			n++
		}
	}
	return n
}
