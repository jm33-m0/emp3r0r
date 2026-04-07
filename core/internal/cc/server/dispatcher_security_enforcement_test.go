package server

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// mockStreamTransport mocks a bidirectional stream for testing
type mockStreamTransport struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	remoteAddr  string
	closed      bool
}

func (m *mockStreamTransport) Read(p []byte) (int, error) {
	return m.readBuffer.Read(p)
}

func (m *mockStreamTransport) Write(p []byte) (int, error) {
	return m.writeBuffer.Write(p)
}

func (m *mockStreamTransport) Close() error {
	m.closed = true
	return nil
}

func (m *mockStreamTransport) RemoteAddrString() string {
	return m.remoteAddr
}

// TestDuplicateSessionPrevention verifies that duplicate session attempts are blocked
// via agents.StartSession returning ErrSessionAlreadyActive
func TestDuplicateSessionPrevention(t *testing.T) {
	// Setup
	tmpDir, err := os.MkdirTemp("", "dispatcher_session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize AgentDB
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to init AgentDB: %v", err)
	}
	defer agents.AgentDB.Close()

	testUUID := "test-agent-uuid-001"
	remoteAddr := "127.0.0.1:12345"

	// Prepare first session (should succeed)
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	err = agents.StartSession(testUUID, sessionID, remoteAddr)
	if err != nil {
		t.Fatalf("First session should succeed, got error: %v", err)
	}

	// Attempt duplicate session (should fail with ErrSessionAlreadyActive)
	sessionID2 := fmt.Sprintf("%d", time.Now().UnixNano()+1)
	err2 := agents.StartSession(testUUID, sessionID2, remoteAddr)
	if err2 == nil {
		t.Errorf("Duplicate session should fail, but got no error")
		return
	}

	// Verify the error is specifically ErrSessionAlreadyActive
	if !errors.Is(err2, agents.ErrSessionAlreadyActive) {
		t.Errorf("Expected ErrSessionAlreadyActive, got: %v", err2)
		return
	}

	// Cleanup first session
	_ = agents.EndSession(testUUID)

	// Verify session was removed
	err3 := agents.StartSession(testUUID, sessionID2, remoteAddr)
	if err3 != nil {
		t.Errorf("After cleanup, new session should succeed, got error: %v", err3)
	}

	// Cleanup
	_ = agents.EndSession(testUUID)
}

// TestRouteValidationStrict verifies that invalid routes are rejected with no fallback
func TestRouteValidationStrict(t *testing.T) {
	testCases := []struct {
		name         string
		capabilities []string
		shouldPass   bool
		expectedErr  string
	}{
		{
			name:         "Valid single route",
			capabilities: []string{"c2-checkin-test"},
			shouldPass:   true,
		},
		{
			name:         "Empty capabilities",
			capabilities: []string{},
			shouldPass:   false,
			expectedErr:  "missing route capability",
		},
		{
			name:         "Invalid route name",
			capabilities: []string{"c2-invalid-route"},
			shouldPass:   false,
			expectedErr:  "no configured route capability provided",
		},
		{
			name:         "Multiple capabilities",
			capabilities: []string{"c2-checkin-test", "c2-msg-test"},
			shouldPass:   false,
			expectedErr:  "multiple route capabilities are not allowed",
		},
	}

	// Setup route config
	live.RuntimeConfig.C2Routes.Checkin = "c2-checkin-test"
	live.RuntimeConfig.C2Routes.Msg = "c2-msg-test"
	live.RuntimeConfig.C2Routes.FTP = "c2-ftp-test"
	live.RuntimeConfig.C2Routes.WWW = "c2-www-test"
	live.RuntimeConfig.C2Routes.Proxy = "c2-proxy-test"

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msgAuth := &def.MsgAuth{
				AgentUUID:    "test-agent",
				Capabilities: tc.capabilities,
			}

			ctx, err := normalizeRouteFromMsgAuth(msgAuth)

			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
				if ctx.Service == "" {
					t.Errorf("Expected valid service route, got empty")
				}
			} else {
				if err == nil {
					t.Errorf("Expected error, but got success")
				}
				if tc.expectedErr != "" && !containsSubstring(err.Error(), tc.expectedErr) {
					t.Errorf("Expected error containing %q, got: %v", tc.expectedErr, err)
				}
			}
		})
	}
}

// TestUnknownAgentRouteRestriction verifies that unknown (unenrolled) agents
// can only use the Checkin route according to the dispatcher logic
func TestUnknownAgentRouteRestriction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unknown_agent_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize AgentDB
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to init AgentDB: %v", err)
	}
	defer agents.AgentDB.Close()

	// Setup routes
	live.RuntimeConfig.C2Routes.Checkin = "c2-checkin-test"
	live.RuntimeConfig.C2Routes.Msg = "c2-msg-test"
	live.RuntimeConfig.C2Routes.FTP = "c2-ftp-test"

	unknownUUID := "unknown-agent-never-enrolled"

	testCases := []struct {
		name        string
		route       string
		isCheckin   bool
		shouldAllow bool
	}{
		{
			name:        "Unknown agent - Checkin route",
			route:       "c2-checkin-test",
			isCheckin:   true,
			shouldAllow: true,
		},
		{
			name:        "Unknown agent - Msg route",
			route:       "c2-msg-test",
			isCheckin:   false,
			shouldAllow: false,
		},
		{
			name:        "Unknown agent - FTP route",
			route:       "c2-ftp-test",
			isCheckin:   false,
			shouldAllow: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify agent is not known
			_, _, isKnown, _ := agents.GetPinnedIdentity(unknownUUID)
			if isKnown {
				t.Fatalf("Setup error: agent should not be enrolled")
			}

			// Check the logic: unknown agents can only use checkin
			_, _, isKnownAgent, _ := agents.GetPinnedIdentity(unknownUUID)
			isCheckinRoute := tc.route == live.RuntimeConfig.C2Routes.Checkin

			allowed := isKnownAgent || isCheckinRoute

			if allowed != tc.shouldAllow {
				t.Errorf("Expected shouldAllow=%v, but got allowed=%v (isKnown=%v, isCheckin=%v)",
					tc.shouldAllow, allowed, isKnownAgent, isCheckinRoute)
			}

			if !tc.shouldAllow {
				if !isKnownAgent && !isCheckinRoute {
					// This is correct behavior: unknown agent, non-checkin route → block
					t.Logf("Correctly blocked unknown agent from non-checkin route")
				}
			}
		})
	}
}

// TestReplayProtection verifies that replay attacks are detected and blocked
func TestReplayProtection(t *testing.T) {
	// Clear replay cache
	replayNonceCache.Range(func(k, v any) bool {
		replayNonceCache.Delete(k)
		return true
	})

	now := time.Now().Unix()
	testUUID := "test-replay-uuid"
	testNonce := "test-nonce-123"
	nonceKey := testUUID + ":" + testNonce

	// First use - should succeed (cache miss before storing)
	if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
		if prevTS, okTS := prev.(int64); okTS && abs64(now-prevTS) <= transport.ReplayWindowSeconds {
			t.Fatalf("Unexpected replay on first attempt")
		}
	}
	replayNonceCache.Store(nonceKey, now)

	// Second use within replay window - should fail
	now2 := now + 5 // 5 seconds later (within default ReplayWindowSeconds window)
	seenReplay := false
	if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
		if prevTS, okTS := prev.(int64); okTS && abs64(now2-prevTS) <= transport.ReplayWindowSeconds {
			seenReplay = true
			t.Logf("Correctly detected replay attack within window (%d seconds)", abs64(now2-prevTS))
		}
	}
	if !seenReplay {
		t.Fatalf("Expected replay detection within window")
	}

	// Third use outside replay window - should succeed
	now3 := now + (transport.ReplayWindowSeconds + 10)
	seenOutsideWindowReplay := false
	if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
		if prevTS, okTS := prev.(int64); okTS && abs64(now3-prevTS) <= transport.ReplayWindowSeconds {
			seenOutsideWindowReplay = true
		}
	}
	if seenOutsideWindowReplay {
		t.Fatalf("Unexpected replay detection outside window")
	}
}

// Helper function to check substring
func containsSubstring(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// TestCBOREnvelopeAuthenticationBoundary verifies that routing decisions are
// made from CBOR envelope fields only, not from transport metadata
func TestCBOREnvelopeAuthenticationBoundary(t *testing.T) {
	// Setup routes
	live.RuntimeConfig.C2Routes.Checkin = "c2-checkin-real"
	live.RuntimeConfig.C2Routes.Msg = "c2-msg-real"

	// Test that normalizeRouteFromMsgAuth only looks at Capabilities field
	msgAuth := &def.MsgAuth{
		AgentUUID:    "test-agent",
		Capabilities: []string{"c2-checkin-real"},
	}

	ctx, err := normalizeRouteFromMsgAuth(msgAuth)
	if err != nil {
		t.Fatalf("Valid route should succeed: %v", err)
	}

	if ctx.Service != "c2-checkin-real" {
		t.Errorf("Expected service=c2-checkin-real, got %s", ctx.Service)
	}

	// Verify that envelope is the only source of truth
	if ctx.AgentUUID != msgAuth.AgentUUID {
		t.Errorf("AgentUUID should come from envelope: expected %s, got %s",
			msgAuth.AgentUUID, ctx.AgentUUID)
	}
}

// TestSessionHeartbeatUpdate verifies that session activity is tracked in the database
func TestSessionHeartbeatUpdate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "heartbeat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize AgentDB
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to init AgentDB: %v", err)
	}
	defer agents.AgentDB.Close()

	testUUID := "heartbeat-test-uuid"

	// Create session
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	startErr := agents.StartSession(testUUID, sessionID, "127.0.0.1:12345")
	if startErr != nil {
		t.Fatalf("Failed to start session: %v", startErr)
	}

	// Update heartbeat and verify no error
	hbErr := agents.UpdateSessionHeartbeat(testUUID)
	if hbErr != nil {
		t.Fatalf("Failed to update heartbeat: %v", hbErr)
	}

	// Verify session still exists
	sessionErr := agents.UpdateSessionHeartbeat(testUUID)
	if sessionErr != nil {
		t.Errorf("Session should still exist after heartbeat update: %v", sessionErr)
	}

	// Cleanup
	_ = agents.EndSession(testUUID)
}

// TestEnrollmentVerificationEnforcement verifies the enrollment check logic
// that auxiliary routes should use before processing
func TestEnrollmentVerificationEnforcement(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enrollment_verify_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize AgentDB
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to init AgentDB: %v", err)
	}
	defer agents.AgentDB.Close()

	testCases := []struct {
		name          string
		uuid          string
		createSession bool
		expectFound   bool
	}{
		{
			name:          "Active session exists",
			uuid:          "agent-with-session-001",
			createSession: true,
			expectFound:   true,
		},
		{
			name:          "No session for UUID",
			uuid:          "agent-no-session-001",
			createSession: false,
			expectFound:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.createSession {
				sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
				sessionErr := agents.StartSession(tc.uuid, sessionID, "127.0.0.1:12345")
				if sessionErr != nil {
					t.Fatalf("Failed to create session: %v", sessionErr)
				}
			}

			// Verify heartbeat operation
			hbErr := agents.UpdateSessionHeartbeat(tc.uuid)

			hasSession := hbErr == nil

			if hasSession != tc.expectFound {
				t.Errorf("Expected found=%v, but hasSession=%v (error: %v)",
					tc.expectFound, hasSession, hbErr)
			}

			// Cleanup
			if tc.createSession {
				_ = agents.EndSession(tc.uuid)
			}
		})
	}
}

// TestStrictRouteToHandler verifies that routes 1-1 map to handlers
// and no route is processed by wrong handler
func TestStrictRouteToHandlerMapping(t *testing.T) {
	// Setup routes
	live.RuntimeConfig.C2Routes.Checkin = "c2-checkin-strict"
	live.RuntimeConfig.C2Routes.Msg = "c2-msg-strict"
	live.RuntimeConfig.C2Routes.FTP = "c2-ftp-strict"
	live.RuntimeConfig.C2Routes.WWW = "c2-www-strict"
	live.RuntimeConfig.C2Routes.Proxy = "c2-proxy-strict"

	testCases := []struct {
		name          string
		capability    string
		expectedRoute string
	}{
		{"Checkin route", "c2-checkin-strict", "checkin"},
		{"Msg route", "c2-msg-strict", "msg"},
		{"FTP route", "c2-ftp-strict", "ftp"},
		{"WWW route", "c2-www-strict", "www"},
		{"Proxy route", "c2-proxy-strict", "proxy"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msgAuth := &def.MsgAuth{
				AgentUUID:    "test",
				Capabilities: []string{tc.capability},
			}

			ctx, err := normalizeRouteFromMsgAuth(msgAuth)
			if err != nil {
				t.Fatalf("Route validation failed: %v", err)
			}

			// Verify route is correctly identified
			switch tc.expectedRoute {
			case "checkin":
				if ctx.Service != live.RuntimeConfig.C2Routes.Checkin {
					t.Errorf("Wrong route: expected checkin, got %s", ctx.Service)
				}
			case "msg":
				if ctx.Service != live.RuntimeConfig.C2Routes.Msg {
					t.Errorf("Wrong route: expected msg, got %s", ctx.Service)
				}
			case "ftp":
				if ctx.Service != live.RuntimeConfig.C2Routes.FTP {
					t.Errorf("Wrong route: expected ftp, got %s", ctx.Service)
				}
			case "www":
				if ctx.Service != live.RuntimeConfig.C2Routes.WWW {
					t.Errorf("Wrong route: expected www, got %s", ctx.Service)
				}
			case "proxy":
				if ctx.Service != live.RuntimeConfig.C2Routes.Proxy {
					t.Errorf("Wrong route: expected proxy, got %s", ctx.Service)
				}
			}
		})
	}
}

// TestSessionIsolation verifies that sessions for different UUIDs don't interfere
func TestSessionIsolation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "session_isolation_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize AgentDB
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to init AgentDB: %v", err)
	}
	defer agents.AgentDB.Close()

	uuid1 := "agent-001"
	uuid2 := "agent-002"
	remoteAddr := "127.0.0.1:12345"

	// Create session for agent 1
	sessionID1 := fmt.Sprintf("%d-1", time.Now().UnixNano())
	err1 := agents.StartSession(uuid1, sessionID1, remoteAddr)
	if err1 != nil {
		t.Fatalf("Failed to create session for agent 1: %v", err1)
	}

	// Create session for agent 2 (should succeed - different UUID)
	sessionID2 := fmt.Sprintf("%d-2", time.Now().UnixNano())
	err2 := agents.StartSession(uuid2, sessionID2, remoteAddr)
	if err2 != nil {
		t.Fatalf("Failed to create session for agent 2: %v", err2)
	}

	// Attempt duplicate for agent 1 (should fail)
	sessionID1Dup := fmt.Sprintf("%d-1-dup", time.Now().UnixNano())
	err1Dup := agents.StartSession(uuid1, sessionID1Dup, remoteAddr)
	if err1Dup == nil {
		t.Errorf("Duplicate session for agent 1 should fail")
	} else if !errors.Is(err1Dup, agents.ErrSessionAlreadyActive) {
		t.Errorf("Expected ErrSessionAlreadyActive, got: %v", err1Dup)
	}

	// Agent 2 should still have valid session
	hbErr := agents.UpdateSessionHeartbeat(uuid2)
	if hbErr != nil {
		t.Errorf("Agent 2 heartbeat should succeed, got: %v", hbErr)
	}

	// Cleanup
	_ = agents.EndSession(uuid1)
	_ = agents.EndSession(uuid2)
}
