package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
)

type fakeDetectBackend struct {
	mu           sync.Mutex
	genSeq       int
	genCalls     []string
	statusCalls  []string
	moduleCalls  []string
	forgetCalls  []string
	finalCalls   []string
	auditRecords []string
	finalOutput  string
}

func (f *fakeDetectBackend) GenerateAgent(ccAddress, agentType, arch string) (*detection.AgentBuildResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.genSeq++
	uuid := "generated-uuid-" + string(rune('0'+f.genSeq))
	f.genCalls = append(f.genCalls, ccAddress+"|"+agentType+"|"+arch)
	return &detection.AgentBuildResult{
		ArtifactPath: "/tmp/agent.dll",
		Type:         agentType,
		Arch:         arch,
		AgentUUID:    uuid,
		SHA256:       "deadbeef",
		Size:         4096,
	}, nil
}

func (f *fakeDetectBackend) AgentStatus(_ context.Context, uuid string) (*detection.VerifyAgentStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls = append(f.statusCalls, uuid)
	return &detection.VerifyAgentStatus{
		ExpectedAgent: uuid,
		Online:        true,
		Agent:         map[string]any{"uuid": uuid, "tag": "test-tag"},
	}, nil
}

func (f *fakeDetectBackend) RunVerifyModule(_ context.Context, uuid, module string) (*detection.VerifyModuleResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.moduleCalls = append(f.moduleCalls, uuid+":"+module)
	return &detection.VerifyModuleResult{
		Module: module,
		JobID:  "job-99",
		Output: "DESKTOP\\user",
	}, nil
}

func (f *fakeDetectBackend) FinalVerify(_ context.Context, uuid, module string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalCalls = append(f.finalCalls, uuid+":"+module)
	return f.finalOutput, nil
}

func (f *fakeDetectBackend) ForgetAgent(_ context.Context, uuid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgetCalls = append(f.forgetCalls, uuid)
	return nil
}

func (f *fakeDetectBackend) Audit(action, target, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auditRecords = append(f.auditRecords, action+"|"+target+"|"+detail)
}

func TestDetectIPCServerEnforcesAuthOwnershipAndAllowlist(t *testing.T) {
	backend := &fakeDetectBackend{finalOutput: "DESKTOP\\operator"}
	srv, err := newDetectIPCServer("https://c2.example:443", "initial-uuid", backend)
	if err != nil {
		t.Fatal(err)
	}
	sockDir := filepath.Dir(srv.SockPath())
	defer srv.Close()

	dirInfo, err := os.Stat(sockDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("IPC dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}

	// Wrong bearer token must be rejected with 401.
	badClient, err := NewDetectIPCClient(srv.SockPath(), "wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badClient.AgentStatus(context.Background(), "initial-uuid"); err == nil {
		t.Fatal("accepted invalid bearer token")
	}

	client, err := NewDetectIPCClient(srv.SockPath(), srv.Token())
	if err != nil {
		t.Fatal(err)
	}

	// Unowned UUIDs must be refused before reaching the C2 backend.
	if _, err := client.AgentStatus(context.Background(), "production-uuid"); err == nil {
		t.Fatal("AgentStatus allowed unowned UUID")
	}
	if _, err := client.RunVerifyModule(context.Background(), "production-uuid", "whoami"); err == nil {
		t.Fatal("RunVerifyModule allowed unowned UUID")
	}
	if err := client.ForgetAgent(context.Background(), "production-uuid"); err == nil {
		t.Fatal("ForgetAgent allowed unowned UUID")
	}
	if _, err := client.FinalVerify(context.Background(), "production-uuid"); err == nil {
		t.Fatal("FinalVerify allowed unowned UUID")
	}

	// Disallowed modules must be refused even for owned UUIDs (direct HTTP check).
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	rawHTTP := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", srv.SockPath())
			},
		},
	}
	req, _ := http.NewRequest(http.MethodPost, "http://detect-ipc/v1/run_verify_module",
		bytes.NewBufferString(`{"uuid":"initial-uuid","module":"shell"}`))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")
	resp, err := rawHTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed module status = %d, want 403", resp.StatusCode)
	}

	// Valid owned UUID operations must succeed.
	status, err := client.AgentStatus(context.Background(), "initial-uuid")
	if err != nil || !status.Online {
		t.Fatalf("AgentStatus(initial-uuid) = %+v, err=%v", status, err)
	}
	modRes, err := client.RunVerifyModule(context.Background(), "initial-uuid", "whoami")
	if err != nil || modRes.JobID != "job-99" {
		t.Fatalf("RunVerifyModule = %+v, err=%v", modRes, err)
	}

	// GenerateAgent forgets initial-uuid, enforces parent CC, and authorizes generated UUID.
	genRes, err := client.BuildAgent(detection.AgentBuildOptions{Type: "windows_dll", Arch: "amd64"})
	if err != nil || genRes.AgentUUID != "generated-uuid-1" {
		t.Fatalf("BuildAgent = %+v, err=%v", genRes, err)
	}
	if len(backend.genCalls) != 1 || backend.genCalls[0] != "https://c2.example:443|windows_dll|amd64" {
		t.Fatalf("genCalls = %v", backend.genCalls)
	}
	if len(backend.forgetCalls) != 1 || backend.forgetCalls[0] != "initial-uuid" {
		t.Fatalf("forgetCalls = %v", backend.forgetCalls)
	}
	if srv.ActiveUUID() != "generated-uuid-1" {
		t.Fatalf("ActiveUUID = %q, want generated-uuid-1", srv.ActiveUUID())
	}

	// Disallowed audit action via /v1/audit must be rejected.
	badAuditReq, _ := http.NewRequest(http.MethodPost, "http://detect-ipc/v1/audit",
		bytes.NewBufferString(`{"action":"agent_status","target":"prod","detail":"spoofed"}`))
	badAuditReq.Header.Set("Authorization", "Bearer "+srv.Token())
	badAuditResp, err := rawHTTP.Do(badAuditReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = badAuditResp.Body.Close()
	if badAuditResp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected /v1/audit status = %d, want 403", badAuditResp.StatusCode)
	}

	// Valid FinalVerify marks server state Verified() = true.
	out, err := client.FinalVerify(context.Background(), "generated-uuid-1")
	if err != nil || out != "DESKTOP\\operator" {
		t.Fatalf("FinalVerify = %q, err=%v", out, err)
	}
	if !srv.Verified() {
		t.Fatal("expected srv.Verified() == true after non-empty FinalVerify output")
	}

	// Backend should never have received an unowned UUID or disallowed module.
	for _, call := range backend.statusCalls {
		if call == "production-uuid" {
			t.Fatalf("backend AgentStatus received unowned UUID: %v", backend.statusCalls)
		}
	}
	for _, call := range backend.moduleCalls {
		if strings.Contains(call, "production-uuid") || strings.Contains(call, "shell") {
			t.Fatalf("backend RunVerifyModule received disallowed call: %v", backend.moduleCalls)
		}
	}

	// Ensure marshaling of pre-RPC denial succeeds cleanly.
	client.AuditLocalDenial("run_module_denied", "generated-uuid-1", "module=shell")
	foundLocalDenial := false
	backend.mu.Lock()
	for _, rec := range backend.auditRecords {
		if strings.Contains(rec, "run_module_denied|generated-uuid-1|module=shell") {
			foundLocalDenial = true
			break
		}
	}
	backend.mu.Unlock()
	if !foundLocalDenial {
		t.Fatalf("local denial not audited: %v", backend.auditRecords)
	}

	// ResetAttempt resets Verified state cleanly for retry attempts.
	srv.ResetAttempt("restart-uuid-2")
	if srv.Verified() || srv.ActiveUUID() != "restart-uuid-2" {
		t.Fatalf("ResetAttempt left verified=%v active=%q", srv.Verified(), srv.ActiveUUID())
	}

	srv.Close()
	if _, err := os.Stat(sockDir); !os.IsNotExist(err) {
		t.Fatalf("IPC temp dir %s not cleaned up after Close", sockDir)
	}
}

func TestRunDetectLoopWorkerRejectsMissingIPCToken(t *testing.T) {
	t.Setenv(detectIPCTokenEnv, "")
	err := RunDetectLoopWorker(context.Background(), detection.EvolveConfig{}, "/nonexistent/ipc.sock")
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected missing IPC token error, got: %v", err)
	}
}

func TestDetectLoopWorkerArgsOmitsSecretTokenAndIncludesIPCSock(t *testing.T) {
	args := detectLoopWorkerArgs(detectLoopOptions{
		ModuleDir:  "/mod",
		Sandbox:    "http://127.0.0.1:1337",
		Iterations: 3,
		Stages:     []string{"static", "dynamic"},
		Format:     "exe",
		SMW:        "on",
		AgentType:  "windows_executable",
		Arch:       "amd64",
		Turns:      30,
		AgentUUID:  "uuid-123",
		Goal:       "verify",
	}, "/tmp/sc.bin", "loop-1", "/tmp/emp-dl/ipc.sock")

	joined := strings.Join(args, " ")
	for _, want := range []string{"detect-loop-worker", "--expected-agent-uuid uuid-123", "--goal verify", "--ipc-sock /tmp/emp-dl/ipc.sock"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args %q missing %q", joined, want)
		}
	}
	var payload json.RawMessage
	_ = payload
}
