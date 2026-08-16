package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// startMessageTunnel launches handleMessageTunnelStream in a goroutine and
// returns a channel that is closed when the handler returns.
func startMessageTunnel(secureConn *transport.SecureConn, dec *cbor.Decoder, remoteAddr string, ctx context.Context, uuid string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleMessageTunnelStream(secureConn, dec, remoteAddr, ctx, uuid)
	}()
	return done
}

// stopMessageTunnel cancels the handler context, closes the provided conns,
// and waits for the handler goroutine to exit so tests never reset package
// globals while handleMessageTunnelStream is still running.
func stopMessageTunnel(t *testing.T, done <-chan struct{}, cancel context.CancelFunc, conns ...net.Conn) {
	t.Helper()
	cancel()
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("message tunnel goroutine did not exit after close")
	}
}

type messageTunnelTestOptions struct {
	remoteAddr string
	timeout    time.Duration
	interval   time.Duration
	lastSeen   time.Time
}

// setupMessageTunnelTestWithOptions prepares AgentDB, an agent in the runtime
// map, an active session and an online operator, and returns the server/client
// side of a net.Pipe tunnel plus a cleanup func.
func setupMessageTunnelTestWithOptions(t *testing.T, uuid string, opts messageTunnelTestOptions) (*transport.SecureConn, *transport.SecureConn, func()) {
	t.Helper()

	if opts.remoteAddr == "" {
		opts.remoteAddr = "127.0.0.1:1"
	}
	if opts.timeout <= 0 {
		opts.timeout = 3 * time.Second
	}
	if opts.interval <= 0 {
		opts.interval = 200 * time.Millisecond
	}

	tmpDir, err := os.MkdirTemp("", "msg_tunnel_lastseen_test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	if err := agents.InitAgentDB(filepath.Join(tmpDir, "agents.db")); err != nil {
		t.Fatalf("init agent db: %v", err)
	}

	agent := &def.Emp3r0rAgent{UUID: uuid, Tag: "test-agent-" + uuid, LastSeen: opts.lastSeen}
	if err := agents.RecordAgentCheckin(agent); err != nil {
		t.Fatalf("record agent checkin: %v", err)
	}
	live.AgentControlMap.Store(agent, &live.AgentControl{Index: 0})

	if err := agents.StartSession(uuid, "test-session", opts.remoteAddr); err != nil {
		t.Fatalf("start session: %v", err)
	}

	OPERATORS.Store("test-operator", &operator_t{sessionID: "test-operator"})
	live.RuntimeConfig.OperatorIdleTimeout = 0

	origTimeout := handshakeTimeout
	origInterval := handshakeCheckInterval
	handshakeTimeout = opts.timeout
	handshakeCheckInterval = opts.interval

	clientConn, serverConn := net.Pipe()
	serverSecure := transport.NewSecureConn(serverConn)
	clientSecure := transport.NewSecureConn(clientConn)

	cleanup := func() {
		handshakeTimeout = origTimeout
		handshakeCheckInterval = origInterval
		live.RuntimeConfig.OperatorIdleTimeout = 1800
		OPERATORS.Delete("test-operator")
		live.AgentControlMap.Delete(agent)
		_ = agents.EndSession(uuid)
		_ = agents.CloseAgentDB()
		_ = serverSecure.Close()
		_ = clientSecure.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return serverSecure, clientSecure, cleanup
}

// setupMessageTunnelTest is the default-options wrapper for
// setupMessageTunnelTestWithOptions.
func setupMessageTunnelTest(t *testing.T, uuid string) (*transport.SecureConn, *transport.SecureConn, func()) {
	t.Helper()
	return setupMessageTunnelTestWithOptions(t, uuid, messageTunnelTestOptions{})
}

// TestMessageTunnelCommandResponseKeepsAlive verifies that a command response
// (Response != nil, no CmdSlice) refreshes the handshake timer, so the tunnel
// is NOT torn down as long as the agent keeps answering commands.
func TestMessageTunnelCommandResponseKeepsAlive(t *testing.T) {
	uuid := "test-uuid-cmd"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)
	deadline := time.Now().Add(3500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := enc.Encode(&def.MsgTunData{Response: []byte("ok")}); err != nil {
			t.Fatalf("encode command response: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Several ticks have fired by now. The command responses must have kept
	// the handshake timer fresh, so the agent must still be connected.
	if _, _, _, found := agents.RuntimeControlByUUID(uuid); !found {
		t.Fatal("agent was disconnected even though it kept sending command responses")
	}
}

// TestMessageTunnelCommandResponseWithOperator verifies the full command
// response path (JobID + operator owner + fwdMsgToOperator) does not block or
// kill the message tunnel.
func TestMessageTunnelCommandResponseWithOperator(t *testing.T) {
	uuid := "test-uuid-cmd-owner"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	opClient, opServer := net.Pipe()
	defer opServer.Close()
	defer opClient.Close()
	OPERATORS.Store("test-operator", &operator_t{sessionID: "test-operator", conn: opServer})
	defer OPERATORS.Delete("test-operator")

	// Drain the operator pipe in the background so async forwards never block.
	go func() {
		dec := cbor.NewDecoder(opClient)
		for {
			var m def.MsgTunData
			if err := dec.Decode(&m); err != nil {
				return
			}
		}
	}()

	setJobOwner("job-1", "test-operator")
	live.CmdTime.Store("job-1", time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"))

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)
	if err := enc.Encode(&def.MsgTunData{JobID: "job-1", Response: []byte("result")}); err != nil {
		t.Fatalf("encode command response: %v", err)
	}

	// Tunnel must still be alive and processing: send a second response and
	// verify the agent is still tracked.
	if err := enc.Encode(&def.MsgTunData{JobID: "job-2", Response: []byte("result2")}); err != nil {
		t.Fatalf("tunnel closed after command response: %v", err)
	}
	if _, _, _, found := agents.RuntimeControlByUUID(uuid); !found {
		t.Fatal("agent was removed after command response forwarding")
	}
}

// TestMessageTunnelSurvivesSetActiveAgent verifies that the operator `target`
// flow (SetActiveAgent + encoding the active agent) does not kill the tunnel.
func TestMessageTunnelSurvivesSetActiveAgent(t *testing.T) {
	uuid := "test-uuid-target"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	// Simulate handleSetActiveAgent (operator `target <agent>`).
	agents.SetActiveAgent("test-agent-" + uuid)
	if _, err := cbor.Marshal(live.ActiveAgent); err != nil {
		t.Fatalf("encode active agent: %v", err)
	}

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := enc.Encode(&def.MsgTunData{Response: []byte("ok")}); err != nil {
			t.Fatalf("tunnel died after SetActiveAgent: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if _, _, _, found := agents.RuntimeControlByUUID(uuid); !found {
		t.Fatal("agent removed after SetActiveAgent")
	}
}

// TestMessageTunnelSilenceTimesOut verifies the negative case: with no agent
// frames at all, the tunnel is torn down and the connection is closed.
func TestMessageTunnelSilenceTimesOut(t *testing.T) {
	uuid := "test-uuid-silent"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	// Send nothing. After the silence timeout the server must close the
	// connection, so a write from the client side must fail.
	select {
	case <-tunnelDone:
	case <-time.After(5 * time.Second):
		t.Fatal("silent agent tunnel did not time out")
	}
	enc := cbor.NewEncoder(clientSecure)
	if err := enc.Encode(&def.MsgTunData{Response: []byte("ok")}); err == nil {
		t.Fatal("silent agent was NOT timed out (connection still open)")
	}

	// A silent tunnel never sets ctrl.Conn, so the handler must still remove
	// the agent from the runtime map. Otherwise the operator list keeps showing
	// it with an ever-growing LastSeen.
	if _, _, _, found := agents.RuntimeControlByUUID(uuid); found {
		t.Fatal("silent agent was not removed from runtime map after silence timeout")
	}
	if connected := agents.GetConnectedAgents(); len(connected) != 0 {
		t.Fatalf("operator list still reports connected agents after silence timeout: %v", connected)
	}
}

// TestMessageTunnelSelectedAgentNoCommandsDies is the regression test for the
// core bug: an agent connects, the operator selects it (SetActiveAgent), but
// the agent is completely silent (no frames sent).  Without a fix the
// lastHandshake timer is never reset, so the tunnel dies after handshakeTimeout
// even though an operator is actively watching.
//
// The test confirms two things:
//  1. A silent, selected agent IS timed out (current and correct behavior —
//     the agent must keep the tunnel alive with keep-alive frames).
//  2. The tunnel dies within the configured handshakeTimeout window, not
//     before (i.e. no premature death within the first tick).
//
// If this test passes but TestMessageTunnelLastSeenUpdatedByKeepalive fails,
// the bug is that silence timeout is correct but LastSeen reporting is wrong.
func TestMessageTunnelSelectedAgentNoCommandsDies(t *testing.T) {
	uuid := "test-uuid-selected-silent"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	// Operator selects the agent.
	agents.SetActiveAgent("test-agent-" + uuid)

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		handleMessageTunnelStream(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	}()

	// Wait for the tunnel to die (should happen after handshakeTimeout = 3s).
	// We allow 5 seconds total to avoid a flaky test; failure is the tunnel
	// staying alive indefinitely.
	select {
	case <-tunnelDone:
		// Good: the silent tunnel was torn down.
	case <-time.After(5 * time.Second):
		t.Fatal("selected-but-silent agent tunnel did NOT time out within 5s")
	}

	// After the tunnel exits, a write to the client side must also fail,
	// confirming the server-side connection was actually closed.
	enc := cbor.NewEncoder(clientSecure)
	if err := enc.Encode(&def.MsgTunData{Response: []byte("probe")}); err == nil {
		t.Error("connection still open after tunnel timeout — server did not close the pipe")
	}
}

// TestMessageTunnelLastSeenUpdatedByKeepalive is the key regression test for
// the "last seen keeps rising" bug.
//
// When an agent is connected and the operator selects it, the displayed
// "last seen" time must advance (i.e. be set to recent time) on every keep-alive
// frame that the agent sends — not only when commands are sent.
//
// Before the fix: agent.LastSeen was only written from the MsgTunData path
// (line 216 in handler_messagetun.go), so any agent sending only MsgAuth
// periodic re-auths would show an ever-growing LastSeen even though the
// connection was alive.
//
// This test sends plain MsgTunData keep-alive frames (the equivalent of a real
// agent's periodic hello ping) and asserts that agent.LastSeen is refreshed
// each time, proving the handler resets it correctly from the data path.
func TestMessageTunnelLastSeenUpdatedByKeepalive(t *testing.T) {
	uuid := "test-uuid-lastseen"
	remoteAddr := "127.0.0.1:2"
	// Register the agent with a deliberately stale LastSeen (10 minutes ago)
	// so we can detect whether the handler resets it.
	staleTime := time.Now().Add(-10 * time.Minute)
	serverSecure, clientSecure, cleanup := setupMessageTunnelTestWithOptions(t, uuid, messageTunnelTestOptions{
		remoteAddr: remoteAddr,
		timeout:    5 * time.Second,
		interval:   200 * time.Millisecond,
		lastSeen:   staleTime,
	})
	defer cleanup()

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, remoteAddr, ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)

	// Send two keep-alive frames separated by 300ms, recording the agent's
	// LastSeen between sends.
	if err := enc.Encode(&def.MsgTunData{Response: []byte("keepalive-1")}); err != nil {
		t.Fatalf("send keepalive-1: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let the server goroutine process it

	// Fetch the live agent entry to read its current LastSeen.
	a1, _, _, found1 := agents.RuntimeControlByUUID(uuid)
	if !found1 {
		t.Fatal("agent not in runtime map after first keepalive")
	}

	firstSeen := a1.LastSeen
	if !firstSeen.After(staleTime) {
		t.Fatalf("LastSeen not updated after first keepalive: got %v, want after %v",
			firstSeen, staleTime)
	}
	t.Logf("LastSeen after keepalive-1: %v (was stale at %v)", firstSeen, staleTime)

	// Send a second keepalive 400ms later; LastSeen must advance further.
	time.Sleep(400 * time.Millisecond)
	before2 := time.Now()
	if err := enc.Encode(&def.MsgTunData{Response: []byte("keepalive-2")}); err != nil {
		t.Fatalf("send keepalive-2: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	a2, _, _, found2 := agents.RuntimeControlByUUID(uuid)
	if !found2 {
		t.Fatal("agent not in runtime map after second keepalive")
	}
	secondSeen := a2.LastSeen
	if !secondSeen.After(before2.Add(-100 * time.Millisecond)) {
		t.Fatalf("LastSeen did not advance after second keepalive: got %v, want after %v",
			secondSeen, before2)
	}
	t.Logf("LastSeen after keepalive-2: %v (must be > %v)", secondSeen, firstSeen)

	// Final sanity: LastSeen must not show 10 minutes of idle.
	idle := time.Since(secondSeen)
	if idle > 30*time.Second {
		t.Fatalf("LastSeen shows %.0fs idle — handler is NOT resetting it on keepalives (the bug)",
			idle.Seconds())
	}
	t.Logf("LastSeen idle: %.1fs — OK", idle.Seconds())
}

// TestMessageTunnelLastSeenOnlyUpdatedByAgentNotByOperator verifies that the
// operator sending a command does NOT itself reset agent.LastSeen — only frames
// received FROM the agent update LastSeen.  This is important to distinguish
// "operator is active" from "agent is alive".
//
// Concretely: after an agent's tunnel starts but the agent is completely silent,
// the agent.LastSeen must remain stale (set at connection time), not be
// refreshed by any operator-side action such as SetActiveAgent or command
// dispatch.  The displayed "last seen" should honestly reflect the last time
// the agent sent a frame.
func TestMessageTunnelLastSeenOnlyUpdatedByAgentNotByOperator(t *testing.T) {
	uuid := "test-uuid-onesided"
	remoteAddr := "127.0.0.1:3"
	// Set a known LastSeen time so we can detect any unexpected update.
	knownTime := time.Now().Add(-5 * time.Minute)
	serverSecure, clientSecure, cleanup := setupMessageTunnelTestWithOptions(t, uuid, messageTunnelTestOptions{
		remoteAddr: remoteAddr,
		// Use a longer timeout so the tunnel doesn't die during our operator-side
		// activity window.
		timeout:  10 * time.Second,
		interval: 200 * time.Millisecond,
		lastSeen: knownTime,
	})
	defer cleanup()

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, remoteAddr, ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	// Operator selects the agent — this should NOT update agent.LastSeen.
	agents.SetActiveAgent("test-agent-" + uuid)

	// Wait a moment so the tunnel has had a chance to process any operator-side
	// state changes.
	time.Sleep(500 * time.Millisecond)

	a, _, _, found := agents.RuntimeControlByUUID(uuid)
	if !found {
		t.Fatal("agent not in runtime map")
	}

	// LastSeen must still reflect the time we set before the tunnel started;
	// operator selection alone must not refresh it.
	if a.LastSeen.After(knownTime.Add(time.Second)) {
		t.Errorf("agent.LastSeen was updated by operator action (SetActiveAgent) without any agent frame: "+
			"got %v, want <= %v — this means LastSeen is not trustworthy as an agent-liveness indicator",
			a.LastSeen, knownTime.Add(time.Second))
	} else {
		t.Logf("Correct: LastSeen unchanged at %v after operator-only actions", a.LastSeen)
	}
}

// TestMessageTunnelHandshakeTimerResetOnKeepalive is a white-box regression
// test for the specific code path that resets lastHandshake.
//
// The bug: lastHandshake is initialised to time.Now() at tunnel start but is
// only reset inside the MsgTunData branch (after agent lookup). If the agent
// sends only periodic MsgAuth re-auths (the normal keep-alive mechanism between
// commands), lastHandshake is never refreshed, so the tunnel dies after 10
// minutes even though the agent is alive.
//
// This test exercises the observable consequence: the tunnel must NOT die
// within handshakeTimeout when keep-alive MsgTunData frames arrive at a rate
// shorter than the timeout, regardless of whether commands are being sent.
//
// The sending rate (every 500ms) is well below the 2s handshakeTimeout, so if
// lastHandshake is NOT reset on each frame the tunnel will die mid-test and
// the send will fail — directly catching the bug.
func TestMessageTunnelHandshakeTimerResetOnKeepalive(t *testing.T) {
	uuid := "test-uuid-hstimer"
	remoteAddr := "127.0.0.1:4"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTestWithOptions(t, uuid, messageTunnelTestOptions{
		remoteAddr: remoteAddr,
		// Short handshake timeout, fast check interval — amplifies the bug.
		timeout:  2 * time.Second,
		interval: 100 * time.Millisecond,
	})
	defer cleanup()

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var processed atomic.Int64

	tunnelDone := startMessageTunnel(serverSecure, dec, remoteAddr, ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)

	// Send keep-alive frames every 500ms for 5 seconds (handshakeTimeout is
	// 2s, check interval 100ms, so ~10 check intervals pass per timeout window).
	// If lastHandshake is NOT reset on every frame, the tunnel dies before we
	// complete the 5-second window and the encode fails — which is the bug.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := enc.Encode(&def.MsgTunData{Response: []byte("ka")}); err != nil {
			t.Fatalf("keepalive send failed after %d frames (tunnel died prematurely — "+
				"lastHandshake was not reset on each frame; this is the bug): %v",
				processed.Load(), err)
		}
		processed.Add(1)
		time.Sleep(500 * time.Millisecond)
	}

	t.Logf("Successfully sent %d keepalive frames over 5s without tunnel dying", processed.Load())

	// The agent must still be tracked after the test window.
	if _, _, _, found := agents.RuntimeControlByUUID(uuid); !found {
		t.Fatal("agent was removed during keepalive window — lastHandshake timer was not being reset")
	}
}

// TestMessageTunnelSelectedAgentWithActiveOperatorSurvivesWithoutCommands verifies that
// an operator selecting an agent and performing operator activity (like polling / set active)
// without sending explicit agent payload commands keeps the operator active and the agent tunnel
// alive and updating LastSeen.
func TestMessageTunnelOperatorIdleRemovesAgent(t *testing.T) {
	uuid := "test-uuid-operator-idle-removes"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	live.RuntimeConfig.OperatorIdleTimeout = 1
	touchOperatorCommand() // operator was active when the tunnel started

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = enc.Encode(&def.MsgTunData{Response: []byte("ka")})
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case <-tunnelDone:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not close after operator idle timeout")
	}

	if _, _, _, found := agents.RuntimeControlByUUID(uuid); found {
		t.Fatal("agent still in runtime map after operator idle teardown")
	}
	if connected := agents.GetConnectedAgents(); len(connected) != 0 {
		t.Fatalf("operator list still reports connected agents after idle teardown: %v", connected)
	}
}

func TestMessageTunnelOperatorIdleRemovesSilentAgent(t *testing.T) {
	uuid := "test-uuid-operator-idle-silent"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	live.RuntimeConfig.OperatorIdleTimeout = 1
	touchOperatorCommand() // operator was active when the tunnel started

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:1", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	// Send nothing. The tunnel should be torn down by operator idle timeout,
	// and the agent must be removed from the operator-facing list even though
	// it never sent a frame on this tunnel.
	select {
	case <-tunnelDone:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not close after operator idle timeout")
	}

	if _, _, _, found := agents.RuntimeControlByUUID(uuid); found {
		t.Fatal("silent agent still in runtime map after operator idle teardown")
	}
	if connected := agents.GetConnectedAgents(); len(connected) != 0 {
		t.Fatalf("operator list still reports connected agents after idle teardown: %v", connected)
	}
}

func TestMessageTunnelSelectedAgentWithActiveOperatorSurvivesWithoutCommands(t *testing.T) {
	uuid := "test-uuid-operator-active-no-cmds"
	serverSecure, clientSecure, cleanup := setupMessageTunnelTest(t, uuid)
	defer cleanup()

	// Enable operator idle timeout (e.g. 2 seconds) and mark operator online.
	live.RuntimeConfig.OperatorIdleTimeout = 2
	defer func() { live.RuntimeConfig.OperatorIdleTimeout = 1800 }()

	MarkOperatorOnline("test-operator")
	defer MarkOperatorOffline("test-operator")

	// Operator selects the agent.
	agents.SetActiveAgent("test-agent-" + uuid)

	dec := cbor.NewDecoder(serverSecure)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnelDone := startMessageTunnel(serverSecure, dec, "127.0.0.1:5", ctx, uuid)
	defer stopMessageTunnel(t, tunnelDone, cancel, serverSecure, clientSecure)

	enc := cbor.NewEncoder(clientSecure)

	// Send keep-alive frames every 500ms over 3.5s (longer than the 2s OperatorIdleTimeout).
	// On each interval, simulate operator activity (touchOperatorCommand / operationDispatcher activity).
	deadline := time.Now().Add(3500 * time.Millisecond)
	for time.Now().Before(deadline) {
		// Simulate operator UI activity (e.g. polling GetAgentList or SetActiveAgent).
		touchOperatorCommand()

		if err := enc.Encode(&def.MsgTunData{Response: []byte("keepalive")}); err != nil {
			t.Fatalf("Tunnel died while operator was active (no commands sent): %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Verify operator is still active and agent LastSeen is fresh.
	if !operatorIsActive() {
		t.Fatal("operatorIsActive returned false despite active operator activity")
	}

	a, _, _, found := agents.RuntimeControlByUUID(uuid)
	if !found {
		t.Fatal("agent disappeared from RuntimeControlByUUID")
	}

	idle := time.Since(a.LastSeen)
	if idle > 2*time.Second {
		t.Fatalf("agent LastSeen is stale: %v", idle)
	}
}
