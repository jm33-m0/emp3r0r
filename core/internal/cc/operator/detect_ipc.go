package operator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	detectIPCTokenEnv      = "EMP3R0R_DETECT_IPC_TOKEN"
	maxDetectIPCBodyBytes  = 1 << 20
	detectIPCServerTimeout = 10 * time.Minute
)

// detectC2Backend executes scoped builder and C2 verification actions in the
// connected operator process.
type detectC2Backend interface {
	GenerateAgent(ccAddress, agentType, arch string) (*detection.AgentBuildResult, error)
	AgentStatus(ctx context.Context, uuid string) (*detection.VerifyAgentStatus, error)
	RunVerifyModule(ctx context.Context, uuid, module string) (*detection.VerifyModuleResult, error)
	FinalVerify(ctx context.Context, uuid, module string) (string, error)
	ForgetAgent(ctx context.Context, uuid string) error
	Audit(action, target, detail string)
}

type liveDetectC2Backend struct{}

func (liveDetectC2Backend) GenerateAgent(ccAddress, agentType, arch string) (*detection.AgentBuildResult, error) {
	return generateDetectionAgentWithCC(ccAddress, detection.AgentBuildOptions{
		Type: agentType,
		Arch: arch,
	})
}

func (liveDetectC2Backend) AgentStatus(_ context.Context, uuid string) (*detection.VerifyAgentStatus, error) {
	agents, err := client.GetAgentList()
	if err != nil {
		return nil, err
	}
	agent := detection.FindAgentByUUID(agents, uuid)
	return &detection.VerifyAgentStatus{
		ExpectedAgent: uuid,
		Online:        agent != nil,
		Agent:         detection.AgentSummary(agent),
	}, nil
}

func (liveDetectC2Backend) RunVerifyModule(ctx context.Context, uuid, module string) (*detection.VerifyModuleResult, error) {
	deadline := time.Now().Add(detection.PayloadVerifyTimeout)
	agents, err := client.GetAgentList()
	if err != nil {
		return nil, err
	}
	agent := detection.FindAgentByUUID(agents, uuid)
	if agent == nil {
		return nil, fmt.Errorf("agent %s is not online; payload is not running", uuid)
	}
	output, jobID, err := runVerifyModuleOnC2(ctx, agent, module, deadline)
	res := &detection.VerifyModuleResult{
		Agent:  detection.AgentSummary(agent),
		Module: module,
		JobID:  jobID,
		Output: output,
	}
	if err != nil {
		res.Message = err.Error()
		return res, err
	}
	return res, nil
}

func (liveDetectC2Backend) FinalVerify(ctx context.Context, uuid, module string) (string, error) {
	deadline := time.Now().Add(detection.PayloadVerifyTimeout)
	agents, err := waitForAgentOnC2(ctx, uuid, deadline)
	if err != nil {
		return "", err
	}
	agent := detection.FindAgentByUUID(agents, uuid)
	if agent == nil {
		return "", fmt.Errorf("agent %s did not come online within %s", uuid, detection.PayloadVerifyTimeout)
	}
	output, _, err := runVerifyModuleOnC2(ctx, agent, module, deadline)
	return output, err
}

func (liveDetectC2Backend) ForgetAgent(_ context.Context, uuid string) error {
	_, err := client.SendCBORRequest(transport.OperatorForgetAgent, def.Operation{
		AgentTag: uuid,
		Action:   "forget_agent",
	})
	return err
}

func (liveDetectC2Backend) Audit(action, target, detail string) {
	auditDetectionAction(action, target, detail)
}

func waitForAgentOnC2(ctx context.Context, want string, deadline time.Time) ([]*def.Emp3r0rAgent, error) {
	for {
		agents, err := client.GetAgentList()
		if err != nil {
			return nil, err
		}
		if want == "" || detection.FindAgentByUUID(agents, want) != nil || time.Now().After(deadline) {
			return agents, nil
		}
		select {
		case <-ctx.Done():
			return agents, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func runVerifyModuleOnC2(ctx context.Context, agent *def.Emp3r0rAgent, module string, deadline time.Time) (string, string, error) {
	if agent == nil {
		return "", "", fmt.Errorf("no agent")
	}
	jobID, err := modules.DispatchModule(agent, module, nil)
	if err != nil {
		return "", "", err
	}
	for {
		resp, err := client.GetJobOutput(jobID, 0, 16<<10, true)
		if err == nil && resp != nil && strings.TrimSpace(resp.Output) != "" {
			return resp.Output, jobID, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return "", jobID, fmt.Errorf("wait for %s output: %w", module, err)
			}
			return "", jobID, fmt.Errorf("%s produced no output before the deadline", module)
		}
		select {
		case <-ctx.Done():
			return "", jobID, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func generateDetectionAgentWithCC(ccAddress string, opts detection.AgentBuildOptions) (*detection.AgentBuildResult, error) {
	// Serialize builder mutations across console generation and worker IPC requests.
	generationMu.Lock()
	defer generationMu.Unlock()

	agentCfg := builder.AgentConfig{}
	if cc := strings.TrimSpace(ccAddress); cc != "" {
		agentCfg.CCAddress = &cc
	}
	res, err := builder.GenerateAgentArtifact(agentCfg, opts.Type, opts.Arch, client.SignAgent)
	if err != nil {
		logging.Warningf("detect_loop: signed agent generation failed (%v); building without a C2 signature", err)
		res, err = builder.GenerateAgentArtifact(agentCfg, opts.Type, opts.Arch, nil)
	}
	if err != nil {
		return nil, err
	}
	if res == nil || strings.TrimSpace(res.OutputFile) == "" {
		return nil, fmt.Errorf("agent build produced no artifact")
	}
	artifact, err := detection.InspectArtifact(res.OutputFile)
	if err != nil {
		return nil, err
	}
	return &detection.AgentBuildResult{
		ArtifactPath: res.OutputFile,
		Type:         opts.Type,
		Arch:         opts.Arch,
		AgentUUID:    res.AgentUUID,
		SHA256:       artifact.SHA256,
		Size:         artifact.Size,
	}, nil
}

// detectIPCServer exposes scoped agent generation and verification endpoints to
// the detached detect-loop-worker over a 0700 Unix domain socket + CSPRNG token.
// All agent UUID ownership and module allowlists are enforced here on the
// parent side so C2 credentials never leave the operator process.
type detectIPCServer struct {
	sockDir  string
	sockPath string
	token    string
	parentCC string
	backend  detectC2Backend
	listener net.Listener
	server   *http.Server

	mu         sync.Mutex
	ownedUUIDs map[string]bool
	activeUUID string
	verified   bool
}

func newDetectIPCServer(parentCC, initialUUID string, backend detectC2Backend) (*detectIPCServer, error) {
	if backend == nil {
		backend = liveDetectC2Backend{}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("generate IPC token: %w", err)
	}
	dir, err := os.MkdirTemp("", "emp-dl-*")
	if err != nil {
		return nil, fmt.Errorf("create IPC dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("chmod IPC dir: %w", err)
	}
	sockPath := filepath.Join(dir, "ipc.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("listen IPC unix socket: %w", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("chmod IPC socket: %w", err)
	}

	s := &detectIPCServer{
		sockDir:    dir,
		sockPath:   sockPath,
		token:      hex.EncodeToString(raw[:]),
		parentCC:   strings.TrimSpace(parentCC),
		backend:    backend,
		listener:   ln,
		ownedUUIDs: make(map[string]bool),
	}
	s.ResetAttempt(initialUUID)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/generate_agent", s.withAuth(s.handleGenerateAgent))
	mux.HandleFunc("/v1/agent_status", s.withAuth(s.handleAgentStatus))
	mux.HandleFunc("/v1/run_verify_module", s.withAuth(s.handleRunVerifyModule))
	mux.HandleFunc("/v1/forget_agent", s.withAuth(s.handleForgetAgent))
	mux.HandleFunc("/v1/final_verify", s.withAuth(s.handleFinalVerify))
	mux.HandleFunc("/v1/audit", s.withAuth(s.handleAudit))

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      detectIPCServerTimeout,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Warningf("detect_loop IPC server error: %v", err)
		}
	}()
	return s, nil
}

func (s *detectIPCServer) SockPath() string { return s.sockPath }
func (s *detectIPCServer) Token() string    { return s.token }

func (s *detectIPCServer) ResetAttempt(initialUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verified = false
	s.activeUUID = strings.TrimSpace(initialUUID)
	if s.activeUUID != "" {
		s.ownedUUIDs[strings.ToLower(s.activeUUID)] = true
	}
}

func (s *detectIPCServer) ActiveUUID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeUUID
}

func (s *detectIPCServer) Verified() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verified
}

func (s *detectIPCServer) Close() {
	if s == nil {
		return
	}
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.server.Shutdown(ctx)
		cancel()
	}
	if s.sockDir != "" {
		_ = os.RemoveAll(s.sockDir)
	}
}

func (s *detectIPCServer) isOwned(uuid string) (string, bool) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return uuid, s.ownedUUIDs[strings.ToLower(uuid)]
}

func (s *detectIPCServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeIPCError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			s.backend.Audit("ipc_auth_denied", r.URL.Path, "missing bearer token")
			writeIPCError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			s.backend.Audit("ipc_auth_denied", r.URL.Path, "invalid bearer token")
			writeIPCError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func decodeIPCJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDetectIPCBodyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxDetectIPCBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxDetectIPCBodyBytes)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

func writeIPCJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeIPCError(w http.ResponseWriter, code int, msg string) {
	writeIPCJSON(w, code, map[string]string{"error": msg})
}

func (s *detectIPCServer) handleGenerateAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string `json:"type"`
		Arch string `json:"arch"`
	}
	if err := decodeIPCJSON(r, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	agentType := strings.ToLower(strings.TrimSpace(req.Type))
	arch := strings.ToLower(strings.TrimSpace(req.Arch))
	switch agentType {
	case builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL:
	default:
		s.backend.Audit("generate_agent_denied", "", "invalid agent_type="+agentType)
		writeIPCError(w, http.StatusBadRequest, "agent_type must be windows_executable or windows_dll")
		return
	}
	if arch != "amd64" {
		s.backend.Audit("generate_agent_denied", "", "invalid arch="+arch)
		writeIPCError(w, http.StatusBadRequest, "arch must be amd64")
		return
	}

	prevUUID := s.ActiveUUID()
	if prevUUID != "" {
		if err := s.backend.ForgetAgent(r.Context(), prevUUID); err != nil {
			logging.Warningf("detect_loop: forget previous agent %s: %v", prevUUID, err)
		}
	}

	res, err := s.backend.GenerateAgent(s.parentCC, agentType, arch)
	if err != nil {
		s.backend.Audit("generate_agent_denied", "", err.Error())
		writeIPCError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.Lock()
	if uuid := strings.TrimSpace(res.AgentUUID); uuid != "" {
		s.activeUUID = uuid
		s.ownedUUIDs[strings.ToLower(uuid)] = true
	}
	s.mu.Unlock()
	s.backend.Audit("generate_agent", res.AgentUUID,
		fmt.Sprintf("type=%s arch=%s artifact=%s", agentType, arch, res.ArtifactPath))
	writeIPCJSON(w, http.StatusOK, res)
}

func (s *detectIPCServer) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID string `json:"uuid"`
	}
	if err := decodeIPCJSON(r, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	targetUUID, ok := s.isOwned(req.UUID)
	if !ok {
		s.backend.Audit("agent_status_denied", req.UUID, "unowned agent UUID")
		writeIPCError(w, http.StatusForbidden, "agent UUID is not owned by this loop")
		return
	}
	status, err := s.backend.AgentStatus(r.Context(), targetUUID)
	if err != nil {
		s.backend.Audit("agent_status_denied", targetUUID, err.Error())
		writeIPCError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status == nil {
		status = &detection.VerifyAgentStatus{ExpectedAgent: targetUUID}
	}
	s.backend.Audit("agent_status", targetUUID, fmt.Sprintf("online=%v", status.Online))
	writeIPCJSON(w, http.StatusOK, status)
}

func (s *detectIPCServer) handleRunVerifyModule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID   string `json:"uuid"`
		Module string `json:"module"`
	}
	if err := decodeIPCJSON(r, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	module := strings.ToLower(strings.TrimSpace(req.Module))
	if !detection.IsAllowedVerifyModule(module) {
		s.backend.Audit("run_module_denied", req.UUID, "module="+module)
		writeIPCError(w, http.StatusForbidden, "module is not allowed")
		return
	}
	targetUUID, ok := s.isOwned(req.UUID)
	if !ok {
		s.backend.Audit("run_module_denied", req.UUID, "unowned agent UUID")
		writeIPCError(w, http.StatusForbidden, "agent UUID is not owned by this loop")
		return
	}
	res, err := s.backend.RunVerifyModule(r.Context(), targetUUID, module)
	if err != nil {
		s.backend.Audit("run_module_denied", targetUUID, fmt.Sprintf("module=%s error=%v", module, err))
		writeIPCError(w, http.StatusBadGateway, err.Error())
		return
	}
	if res == nil {
		res = &detection.VerifyModuleResult{Module: module}
	}
	s.backend.Audit("run_module", targetUUID, fmt.Sprintf("module=%s job=%s", module, res.JobID))
	writeIPCJSON(w, http.StatusOK, res)
}

func (s *detectIPCServer) handleForgetAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID string `json:"uuid"`
	}
	if err := decodeIPCJSON(r, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	targetUUID, ok := s.isOwned(req.UUID)
	if !ok {
		s.backend.Audit("cleanup_agent_denied", req.UUID, "unowned agent UUID")
		writeIPCError(w, http.StatusForbidden, "agent UUID is not owned by this loop")
		return
	}
	if err := s.backend.ForgetAgent(r.Context(), targetUUID); err != nil {
		s.backend.Audit("cleanup_agent_denied", targetUUID, err.Error())
		writeIPCError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.backend.Audit("cleanup_agent", targetUUID, "")
	writeIPCJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *detectIPCServer) handleFinalVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID   string `json:"uuid"`
		Module string `json:"module"`
	}
	if err := decodeIPCJSON(r, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	module := strings.ToLower(strings.TrimSpace(req.Module))
	if module == "" {
		module = detection.DefaultVerifyModule
	}
	if !detection.IsAllowedVerifyModule(module) {
		s.backend.Audit("final_verify_denied", req.UUID, "module="+module)
		writeIPCError(w, http.StatusForbidden, "module is not allowed")
		return
	}
	targetUUID, ok := s.isOwned(req.UUID)
	if !ok {
		s.backend.Audit("final_verify_denied", req.UUID, "unowned agent UUID")
		writeIPCError(w, http.StatusForbidden, "agent UUID is not owned by this loop")
		return
	}
	output, err := s.backend.FinalVerify(r.Context(), targetUUID, module)
	verified := err == nil && strings.TrimSpace(output) != ""
	s.mu.Lock()
	s.verified = verified
	s.mu.Unlock()
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	s.backend.Audit("final_verify", targetUUID, fmt.Sprintf("module=%s verified=%v error=%v", module, verified, err))
	writeIPCJSON(w, http.StatusOK, map[string]any{
		"output": output,
		"error":  errText,
	})
}

func (s *detectIPCServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Target string `json:"target"`
		Detail string `json:"detail"`
	}
	if err := decodeIPCJSON(r, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	switch req.Action {
	case "agent_status_denied", "run_module_denied", "cleanup_agent_denied",
		"generate_agent_denied", "final_verify_denied":
	default:
		writeIPCError(w, http.StatusForbidden, "audit action is not allowed")
		return
	}
	s.backend.Audit(req.Action, req.Target, req.Detail)
	writeIPCJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// DetectIPCClient implements detection.VerifyOps, BuildAgent, FinalVerify, and
// pre-RPC denial auditing in the detached worker without holding C2 credentials.
type DetectIPCClient struct {
	token string
	http  *http.Client
}

// NewDetectIPCClient connects to the parent operator's scoped Unix IPC socket.
func NewDetectIPCClient(sockPath, token string) (*DetectIPCClient, error) {
	sockPath = strings.TrimSpace(sockPath)
	token = strings.TrimSpace(token)
	if sockPath == "" || token == "" {
		return nil, fmt.Errorf("IPC socket path and token are required")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", sockPath)
		},
	}
	return &DetectIPCClient{
		token: token,
		http:  &http.Client{Transport: tr, Timeout: detectIPCServerTimeout},
	}, nil
}

func (c *DetectIPCClient) call(ctx context.Context, path string, reqBody, respBody any) error {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encode IPC request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://detect-ipc"+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build IPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("IPC %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDetectIPCBodyBytes))
	if err != nil {
		return fmt.Errorf("read IPC response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errObj struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &errObj) == nil && errObj.Error != "" {
			return errors.New(errObj.Error)
		}
		return fmt.Errorf("IPC %s returned HTTP %d", path, resp.StatusCode)
	}
	if respBody != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, respBody); err != nil {
			return fmt.Errorf("decode IPC response: %w", err)
		}
	}
	return nil
}

func (c *DetectIPCClient) BuildAgent(opts detection.AgentBuildOptions) (*detection.AgentBuildResult, error) {
	var res detection.AgentBuildResult
	err := c.call(context.Background(), "/v1/generate_agent", map[string]string{
		"type": opts.Type,
		"arch": opts.Arch,
	}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *DetectIPCClient) AgentStatus(ctx context.Context, agentUUID string) (*detection.VerifyAgentStatus, error) {
	var res detection.VerifyAgentStatus
	if err := c.call(ctx, "/v1/agent_status", map[string]string{"uuid": agentUUID}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *DetectIPCClient) RunVerifyModule(ctx context.Context, agentUUID, module string) (*detection.VerifyModuleResult, error) {
	var res detection.VerifyModuleResult
	err := c.call(ctx, "/v1/run_verify_module", map[string]string{
		"uuid":   agentUUID,
		"module": module,
	}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *DetectIPCClient) ForgetAgent(ctx context.Context, agentUUID string) error {
	return c.call(ctx, "/v1/forget_agent", map[string]string{"uuid": agentUUID}, nil)
}

func (c *DetectIPCClient) FinalVerify(ctx context.Context, agentUUID string) (string, error) {
	var res struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	err := c.call(ctx, "/v1/final_verify", map[string]string{
		"uuid":   agentUUID,
		"module": detection.DefaultVerifyModule,
	}, &res)
	if err != nil {
		return "", err
	}
	if res.Error != "" {
		return res.Output, errors.New(res.Error)
	}
	return res.Output, nil
}

// AuditLocalDenial forwards pre-RPC worker validation denials to the parent
// operator audit log without duplicating parent-side RPC audit entries.
func (c *DetectIPCClient) AuditLocalDenial(action, target, detail string) {
	switch action {
	case "run_module_denied", "agent_status_denied", "cleanup_agent_denied":
	default:
		return
	}
	if detail == "" || (!strings.HasPrefix(detail, "module=") &&
		!strings.HasPrefix(detail, "no expected agent UUID") &&
		!strings.HasPrefix(detail, "verification is not configured")) {
		return
	}
	_ = c.call(context.Background(), "/v1/audit", map[string]string{
		"action": action,
		"target": target,
		"detail": detail,
	}, nil)
}
