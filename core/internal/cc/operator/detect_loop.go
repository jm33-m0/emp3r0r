package operator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// detectLoopCmd starts the autonomous Norma detection loop in the operator
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
		Short:   "Autonomously build, detonate, edit, and re-test a payload with Norma",
		Long: `Start the autonomous detection loop for loader_windows or stager_linux.

The command generates a real agent when --shellcode is omitted, then starts the
loop. For loader_windows it builds a Go Windows agent and wraps it with a
shellcode producer; for stager_linux it builds the C agent PIC from the editable
c_agent tree and embeds it in an executable stager. The loop builds the module
from --module-dir, detonates it in LitterBox (Windows) or PenguinBox (Linux), and
runs three Norma workers: a planner that chooses one mechanism and prediction,
an editor that applies every source or producer edit the change needs and
detonates one cycle, and a debugger that inspects the sandbox when the payload
did not execute. Agent generation and C2 verification use the console's
existing connection.

Select the Linux payload with --module stager_linux and a --module-dir that
points at core/modules/stager_linux. The C agent source defaults to the sibling
core/c_agent and is a writable source root. The Linux sandbox API is the
LitterBox-compatible PenguinBox endpoint; point --sandbox at the SSH tunnel, for
example 127.0.0.1:1338, and set --cc to an address the guest can reach
(use host.containers.internal, or its guest-visible address, for a C2 on the
operator host; 10.0.2.2 is the PenguinBox container, not the host). Linux always
uses the shipped malasada module; --producer paths are Windows-only. It does
not use the Windows guest-SSH debugger.

--shellcode accepts any x64 position-independent shellcode for loader_windows,
or the C agent PIC for stager_linux. Without it, the loop generates the matching
agent. For a Windows EXE it wraps with donut. Pass --agent-type windows_dll to
build a DLL agent instead; it is wrapped with crystal_pack when the Crystal
Palace distribution, Java, and its build toolchain are installed, and with donut
otherwise. A Linux loop always uses --agent-type linux_so. Norma can
change the loader, wrapper, injection path, Windows shellcode producer, stager,
or C agent when telemetry points at that design.

The loop imports every saved LitterBox analyzer result: RedEdr, Moneta,
pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA, CheckPlz, HolyGrail, and
every EDR profile. A PenguinBox result is imported as Tracee syscall/LSM events
and Falco alerts, with ELF and YARA static findings. Full feedback, builds, and
per-payload telemetry stay in one SQLite store, tagged with the trace platform.
The loop writes only its instructions and bounded tool results to the model
context.

Enable the debugger with --guest-ssh user@host:port and --guest-ssh-key. There
is no implicit host. The debugger uses public-key SSH into the sandbox guest,
verifies or adds the Defender exclusion for --guest-ssh-exclude (default
C:\\LitterBox\\emp-debug), and may launch an uploaded artifact, read logs and
dumps, and test C2 reachability. It cannot edit module source. The guest is the
sandbox: the debugger may change its detection settings when they block
execution and records every change; such a cycle is debug-assisted.

--debugger-policy selects when it runs. final (default) reserves one pass for
the stop decision, after the last payload has been rolled back; cycle restores
the older behaviour of one pass after every non-executing cycle; off disables
the debugger. A payload relaunched manually by the debugger does not become a
verified baseline: the cycle stays offline and is not used for score
comparisons or source restore.

The loop records source history in a shadow go-git repository under the
detection store; no git binary is required. Pass --git=false to disable it.

The workers can edit module and producer source, and the build scripts and
generators they edit run on this host with operator privileges. Treat the loop
as a code-execution feature controlled by an untrusted model, not as a
sandbox: run it in a dedicated, disposable VM or container with no host
credentials, no production C2 keys, and restricted network egress.

Source-edit review, payload reversion, and the loop prompt reduce exposure but
do not contain the model. build.sh, Makefile, config.json, generated source, and
other build inputs can execute commands with operator privileges. The prompt is
a soft guardrail against prompt injection, not a boundary. Complete isolation
is the only reliable control.

Manage running and on-disk loops with detect_loop list, resume a stopped loop
with detect_loop resume <loop-id>, stop one with detect_loop stop <loop-id> or
--all, and queue an instruction with detect_loop prompt <loop-id> <instruction>.

Set the model through the environment:
  EMP3R0R_DETECTION_PROVIDER=openai-responses
  EMP3R0R_DETECTION_MODEL=<model>
  EMP3R0R_DETECTION_BASE_URL=<url>
  OPENAI_API_KEY=<key>`,
		Example: "detect_loop --module loader_windows --module-dir /path/to/core/modules/loader_windows --iterations 3\n  detect_loop --module stager_linux --module-dir /path/to/core/modules/stager_linux --sandbox 127.0.0.1:1338 --cc host.containers.internal",
		Args:    cobra.NoArgs,
		Run:     runDetectLoopCommand,
	}
	addDetectLoopFlags(cmd)
	cmd.AddCommand(
		KnowledgeSyncCmd(),
		detectLoopStartCmd(),
		detectLoopListCmd(),
		detectLoopResumeCmd(),
		detectLoopStopCmd(),
		detectLoopPromptCmd(),
	)
	return cmd
}

// addDetectLoopFlags registers the build/detonation options shared by
// `detect_loop` and its explicit `start` alias.
func addDetectLoopFlags(cmd *cobra.Command) {
	cmd.Flags().String("module", "", "Payload module: loader_windows or stager_linux (default: derived from --module-dir, else loader_windows)")
	cmd.Flags().String("module-dir", "", "Module source directory (default: the installed module path)")
	cmd.Flags().String("agent-source-dir", "", "Editable C agent source for stager_linux (default: <repo>/c_agent)")
	cmd.Flags().String("shellcode", "", "Windows x64 PIC shellcode or the Linux C agent PIC; generated when omitted")
	cmd.Flags().String("agent-type", "auto", "Agent payload type: auto, windows_executable, windows_dll, or linux_so")
	cmd.Flags().String("arch", "amd64", "Agent architecture")
	cmd.Flags().String("agent-glibc", "2.17", "Linux C agent oldest glibc ABI: 2.17 or 2.34")
	cmd.Flags().String("agent-dynload", "auto", "Linux C agent dynload mode: auto, libc_dl, or public")
	cmd.Flags().String("agent-libc", "glibc", "Linux C agent libc: glibc or musl")
	cmd.Flags().String("cc", "", "C2 address for the generated agent; defaults to the configured address and is used verbatim")
	cmd.Flags().String("sandbox", "", "LitterBox-compatible lab URL; defaults to the platform entry in labs.json")
	cmd.Flags().Int("iterations", 3, "Maximum detection cycles across attempts, including each baseline")
	cmd.Flags().StringSlice("stages", []string{"static", "dynamic"}, "Stages to run: static, dynamic, edr")
	cmd.Flags().String("process", "", "Override the sacrificial process; empty uses the module default")
	cmd.Flags().String("format", "exe", "Windows loader host format: exe, service, or dll; stager_linux always builds an executable")
	cmd.Flags().String("inject", "", "Override the injection method; empty uses the module default")
	cmd.Flags().String("smw", "on", "SilentMoonwalk: on or off")
	cmd.Flags().StringSlice("producer", nil, "Shellcode producer as name or name=path (donut, crystal_pack, name=/path); a bare name uses the installed module")
	cmd.Flags().StringSlice("read-root", nil, "Read-only source root the model may inspect (repeatable)")
	cmd.Flags().String("knowledge", "", "Knowledge cache path; defaults to <detection store>/knowledge.db")
	cmd.Flags().Int("turns", 60, "Default per-worker turn cap; overridden by the role flags")
	cmd.Flags().Int("planner-turns", 24, "Maximum planner turns per session")
	cmd.Flags().Duration("planner-timeout", 10*time.Minute, "Hard decision window for one planner decision; the planner is forced to return its JSON plan when it expires")
	cmd.Flags().Int("planner-read-budget", 12, "Read-only calls before the planner must return a plan; negative disables the cap")
	cmd.Flags().Int("editor-read-budget", 12, "Read-only calls without an edit before the editor loses read tools; negative disables the cap")
	cmd.Flags().Int("debugger-tool-budget", 0, "Total tool calls per debugger pass; 0 means no cap (turn and time limits still apply)")
	cmd.Flags().Duration("editor-timeout", 15*time.Minute, "Decision window for one editor session; the editor is forced to apply the edit and call DetectionCycle when it expires")
	cmd.Flags().Int("editor-turns", 60, "Maximum editor turns per session")
	cmd.Flags().Int("debugger-turns", 24, "Maximum debugger turns per session")
	cmd.Flags().Duration("debugger-timeout", 15*time.Minute, "Wall-clock limit for one debugger pass")
	cmd.Flags().String("debugger-policy", "final", "When the guest debugger runs: final (one pass at the stop), cycle (after every non-executing cycle), or off")
	cmd.Flags().Float64("input-price", 0, "USD per 1M input tokens for the cost estimate; 0 leaves the rate unset")
	cmd.Flags().Float64("output-price", 0, "USD per 1M output tokens for the cost estimate; 0 leaves the rate unset")
	cmd.Flags().Float64("cache-read-price", 0, "USD per 1M cache-read tokens for the cost estimate; 0 leaves the rate unset")
	cmd.Flags().Float64("cache-write-price", 0, "USD per 1M cache-write tokens for the cost estimate; 0 leaves the rate unset")
	cmd.Flags().StringToString("worker-model", nil, "Per-worker model override, for example planner=...,editor=...,debugger=...")
	cmd.Flags().String("guest-ssh", "", "Sandbox guest SSH endpoint as user@host:port; defaults to guest_ssh in labs.json")
	cmd.Flags().String("guest-ssh-key", "", "Sandbox-only SSH private key; defaults to guest_ssh_key in labs.json")
	cmd.Flags().String("guest-ssh-exclude", "", "Defender exclusion and debug staging path; defaults to guest_ssh_exclude in labs.json")
	cmd.Flags().String("guest-ssh-known-hosts", "", "TOFU known-hosts file; defaults under the detection store")
	cmd.Flags().String("guest-ssh-fingerprint", "", "Pin the guest host key as SHA256:...")
	cmd.Flags().Bool("guest-ssh-insecure", false, "Disable guest host-key verification (not recommended)")
	cmd.Flags().Duration("guest-ssh-timeout", 60*time.Second, "Guest command timeout")
	cmd.Flags().Bool("git", true, "Record source edits in a shadow git repository under the detection store")
	cmd.Flags().Duration("timeout", 0, "Loop deadline; 0 means no deadline")
	cmd.Flags().Duration("cycle-timeout", 60*time.Minute, "Deadline for one build, detonation, and verification cycle")
	cmd.Flags().Duration("session-timeout", 2*time.Hour, "Wall-clock deadline for one model session")
	cmd.Flags().Duration("tool-idle-timeout", 30*time.Minute, "Continue a model session that makes no tool call for this long")
	cmd.Flags().Bool("tmux", true, "Open a separate tmux window tailing the loop log")
	cmd.Flags().String("goal", "", "High-level loop goal shown to the model")

	_ = cmd.RegisterFlagCompletionFunc("inject", completeFlagValues("apc", "ct", "self"))
	_ = cmd.RegisterFlagCompletionFunc("format", completeFlagValues("exe", "service", "dll"))
	_ = cmd.RegisterFlagCompletionFunc("agent-type", completeFlagValues("auto", builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL, "linux_so"))
	_ = cmd.RegisterFlagCompletionFunc("arch", completeFlagValues("amd64"))
	_ = cmd.RegisterFlagCompletionFunc("smw", completeFlagValues("on", "off"))
	_ = cmd.RegisterFlagCompletionFunc("stages", completeFlagValues("static", "dynamic"))
	_ = cmd.RegisterFlagCompletionFunc("debugger-policy", completeFlagValues("final", "cycle", "off"))
	_ = cmd.RegisterFlagCompletionFunc("process", completeFlagValues("dllhost.exe", "notepad.exe", "svchost.exe", "explorer.exe", "rundll32.exe"))
	_ = cmd.RegisterFlagCompletionFunc("producer", completeFlagValues("donut", "crystal_pack"))
	_ = cmd.RegisterFlagCompletionFunc("module", completeFlagValues("loader_windows", "stager_linux"))
	_ = cmd.RegisterFlagCompletionFunc("agent-source-dir", completeFlagDirs)
	_ = cmd.RegisterFlagCompletionFunc("module-dir", completeFlagDirs)
	_ = cmd.RegisterFlagCompletionFunc("read-root", completeFlagDirs)
	_ = cmd.RegisterFlagCompletionFunc("shellcode", completeFlagFiles)
	_ = cmd.RegisterFlagCompletionFunc("knowledge", completeFlagFiles)
}

func detectLoopStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "start",
		Aliases: []string{"launch"},
		Short:   "Start a detection loop (same options as detect_loop)",
		Args:    cobra.NoArgs,
		Run:     runDetectLoopCommand,
	}
	addDetectLoopFlags(cmd)
	return cmd
}

func detectLoopListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List running and on-disk detection loops, attempts, status, and logs",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			infos := listDetectRunInfos()
			asJSON, _ := cmd.Flags().GetBool("json")
			if asJSON {
				data, err := json.MarshalIndent(infos, "", "  ")
				if err != nil {
					logging.Errorf("detect_loop list: %v", err)
					return
				}
				cmd.Println(string(data))
				return
			}
			if len(infos) == 0 {
				logging.Infof("detect_loop: no loops are running or on disk")
				return
			}
			for _, row := range detectRunInfoRows(infos) {
				cmd.Println(row)
			}
		},
	}
	cmd.Flags().Bool("json", false, "Print the loop registry as JSON")
	return cmd
}

func detectLoopResumeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "resume <loop-id>",
		Aliases: []string{"continue"},
		Short:   "Resume a stopped or interrupted loop from its on-disk state",
		Args:    cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			if loaded, err := live.LoadOperatorEnv(); err != nil {
				logging.Warningf("detect_loop resume: load operator env: %v", err)
			} else if loaded > 0 {
				logging.Infof("detect_loop resume: loaded %d operator env values", loaded)
			}
			manifest, err := readDetectLoopManifest(args[0])
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					logging.Errorf("detect_loop resume: no on-disk state for %s; only loops started with a saved manifest can resume", args[0])
					return
				}
				logging.Errorf("detect_loop resume: %v", err)
				return
			}
			if manifest.Verified || !detectLoopResumable(manifest.Status) {
				logging.Errorf("detect_loop resume: loop %s is already %s; start a new loop instead", args[0], manifest.Status)
				return
			}
			baseID := strings.TrimSpace(manifest.BaseLoopID)
			if baseID == "" {
				baseID = manifest.LoopID
			}
			nextAttempt := manifest.Attempt + 1
			if nextAttempt < 2 {
				nextAttempt = 2
			}
			if run := findDetectRun(baseID); run != nil {
				if !run.isDone() {
					logging.Errorf("detect_loop resume: loop %s is still %s", baseID, run.status())
					return
				}
				if !detectLoopResumable(run.status()) {
					logging.Errorf("detect_loop resume: loop %s is already %s; start a new loop instead", baseID, run.status())
					return
				}
			}
			if err := removeFinishedDetectRun(baseID); err != nil {
				logging.Errorf("detect_loop resume: %v", err)
				return
			}
			if run := findDetectRun(baseID); run != nil {
				logging.Errorf("detect_loop resume: loop %s is still %s", baseID, run.status())
				return
			}
			opts := manifest.Options
			if opts.Iterations <= 0 {
				opts.Iterations = 3
			}
			if opts.Module == "" {
				opts.Module = filepath.Base(filepath.Clean(opts.ModuleDir))
			}
			opts.Module = strings.ToLower(strings.TrimSpace(opts.Module))
			opts.Platform = detection.PlatformForModule(opts.Module)
			if opts.Platform == "linux" {
				if opts.AgentSourceDir == "" {
					opts.AgentSourceDir = detection.DefaultAgentSourceDir(opts.ModuleDir)
				}
				if abs, absErr := filepath.Abs(opts.AgentSourceDir); absErr == nil {
					opts.AgentSourceDir = abs
				}
				opts.AgentType = "linux_so"
			} else if opts.AgentType == "" || opts.AgentType == "auto" {
				opts.AgentType = "windows_executable"
			}
			if err := applyDetectLoopLabs(&opts); err != nil {
				logging.Errorf("detect_loop resume: load labs: %v", err)
				return
			}
			if strings.TrimSpace(opts.ModuleDir) == "" {
				logging.Errorf("detect_loop resume: the saved loop has no module directory")
				return
			}
			if info, err := os.Stat(opts.ModuleDir); err != nil || !info.IsDir() {
				logging.Errorf("detect_loop resume: module directory %q is not readable", opts.ModuleDir)
				return
			}
			if !detection.ModelConfigured() {
				logging.Errorf("detect_loop resume: no detection model configured; set EMP3R0R_DETECTION_MODEL and the provider API key")
				return
			}
			currentID := fmt.Sprintf("%s-r%d", baseID, nextAttempt)
			if resumeCycleBudgetExhausted(baseID, currentID, nextAttempt, opts.Iterations) {
				logging.Errorf("detect_loop resume: loop %s has used its cycle budget (%d); start a new loop", baseID, opts.Iterations)
				return
			}
			logPath := detectLoopLogPath(manifest.LogPath)
			if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
				logging.Errorf("detect_loop resume: create log directory: %v", err)
				return
			}
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				logging.Errorf("detect_loop resume: open log: %v", err)
				return
			}
			if err := logFile.Chmod(0o600); err != nil {
				_ = logFile.Close()
				logging.Errorf("detect_loop resume: secure log: %v", err)
				return
			}
			logger := newLoopLogger(logFile)
			logf := logger.printf
			if opts.Tmux {
				if _, tmuxErr := cli.TmuxNewPane(detectLoopWindowTitle(currentID), "", "", 0, loopTailCommand(logPath)); tmuxErr != nil {
					logging.Warningf("detect_loop resume: tmux window: %v", tmuxErr)
				}
			}
			prompts := detection.NewOperatorPromptQueue()
			run, err := registerDetectRun(baseID, prompts, logPath, logger)
			if err != nil {
				logger.close()
				logging.Errorf("detect_loop resume: %v", err)
				return
			}
			run.setCurrent(currentID, nextAttempt)
			saveLoopManifest(baseID, currentID, nextAttempt, "running", opts, run)
			logf("resuming loop %s at attempt %d", baseID, nextAttempt)
			logging.Infof("Detection loop %s resumed at attempt %d; log: %s", baseID, nextAttempt, logPath)
			go func() {
				shellcode := strings.TrimSpace(opts.Shellcode)
				if shellcode == "" || !fileExists(shellcode) {
					if shellcode != "" && !opts.ShellcodeGenerated {
						run.setError(fmt.Errorf("resume: operator-supplied shellcode %s is missing", shellcode))
						saveLoopManifest(baseID, currentID, nextAttempt, "failed", opts, run)
						run.finish()
						return
					}
					logf("resuming without a usable shellcode; generating a fresh agent")
					generated, agentArtifact, producer, agentType, agentUUID, genErr := generateAgentShellcode(opts, logf)
					if genErr != nil {
						run.setError(fmt.Errorf("resume shellcode generation: %w", genErr))
						saveLoopManifest(baseID, currentID, nextAttempt, "failed", opts, run)
						run.finish()
						return
					}
					shellcode = generated
					opts.Shellcode = generated
					opts.AgentArtifact = agentArtifact
					opts.ShellcodeGenerated = true
					opts.AgentType = agentType
					opts.ShellcodeProducer = producer
					opts.AgentUUID = agentUUID
					saveLoopManifest(baseID, currentID, nextAttempt, "running", opts, run)
				}
				runDetectLoop(run, opts, shellcode, baseID, nextAttempt, nextAttempt)
			}()
		},
	}
}

// resumeCycleBudgetExhausted checks the saved cycle budget before generating a
// new agent and shellcode. RunEvolve performs the same check later; doing it
// here avoids touching the builder and C2 for a resumed loop that cannot run.
func resumeCycleBudgetExhausted(baseID, currentID string, attempt, total int) bool {
	if total <= 0 || strings.TrimSpace(baseID) == "" {
		return false
	}
	db, err := detection.OpenTelemetryDB(filepath.Join(live.EmpWorkSpace, "detection", "telemetry.db"))
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	cycles, err := db.CyclesForLogicalLoop(context.Background(), baseID, currentID, attempt)
	if err != nil {
		return false
	}
	return len(cycles) >= total
}

func fileExists(path string) bool {
	info, err := os.Stat(strings.TrimSpace(path))
	return err == nil && info.Mode().IsRegular()
}

func detectLoopStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop <loop-id> | --all",
		Short: "Cancel one detection loop or every running loop",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			all, _ := cmd.Flags().GetBool("all")
			if all && len(args) > 0 {
				logging.Errorf("detect_loop stop: pass either a loop id or --all, not both")
				return
			}
			if !all && len(args) == 0 {
				logging.Errorf("detect_loop stop: pass a loop id or --all")
				return
			}
			if all {
				runs := listDetectRuns()
				stopped := 0
				for _, run := range runs {
					if run.isDone() {
						continue
					}
					info, wasRunning, err := stopDetectRun(run.id, 5*time.Second)
					if err != nil {
						logging.Warningf("detect_loop stop %s: %v", run.id, err)
						continue
					}
					if wasRunning {
						stopped++
					}
					logging.Infof("detect_loop: stopped %s (%s)", info.LoopID, info.Status)
				}
				logging.Infof("detect_loop: stop requested for %d loop(s)", stopped)
				return
			}
			info, wasRunning, err := stopDetectRun(args[0], 5*time.Second)
			if err != nil {
				logging.Errorf("detect_loop stop: %v", err)
				return
			}
			if wasRunning {
				logging.Warningf("detect_loop: stopped %s (%s)", info.LoopID, info.Status)
			} else {
				logging.Infof("detect_loop: %s was already finished (%s)", info.LoopID, info.Status)
			}
		},
	}
	cmd.Flags().Bool("all", false, "Cancel every detection loop")
	return cmd
}

func detectLoopPromptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "prompt <loop-id> <instruction...>",
		Short: "Append an operator instruction to a detection loop",
		Long: `Append an instruction to a loop's prompt queue.

The loop reads new instructions before its next model session and includes them
in the next DetectionCycle result. It cannot interrupt an in-flight model turn or
sandbox run, so use detect_loop stop for immediate termination.`,
		Args: cobra.MinimumNArgs(2),
		Run: func(_ *cobra.Command, args []string) {
			text := strings.Join(args[1:], " ")
			info, err := appendDetectRunPrompt(args[0], text)
			if err != nil {
				logging.Errorf("detect_loop prompt: %v", err)
				return
			}
			logging.Successf("detect_loop: prompt queued for %s (attempt %d, %d pending)",
				info.LoopID, info.Attempt, info.Prompts)
		},
	}
}

type detectLoopOptions struct {
	Module         string
	ModuleDir      string
	Platform       string
	AgentSourceDir string
	Shellcode      string
	// AgentArtifact is the agent executable or DLL wrapped into Shellcode.
	// The loop deletes it when it rotates the test agent.
	AgentArtifact string
	// ShellcodeGenerated marks Shellcode as a loop artifact, not an
	// operator-supplied file, so rotation may delete it.
	ShellcodeGenerated bool
	// ShellcodeProducer is the module that generated Shellcode when the
	// parent process built it, so the loop can tell the model which
	// producer source describes the blob.
	ShellcodeProducer string
	// AgentUUID is the identity of the generated baseline agent. The loop
	// uses it to prove that this payload checked in and can run a module.
	AgentUUID           string
	AgentType           string
	Arch                string
	AgentGlibc          string
	AgentDynload        string
	AgentLibc           string
	CC                  string
	Sandbox             string
	Iterations          int
	Stages              []string
	Process             string
	Format              string
	Inject              string
	SMW                 string
	Producers           []string
	ReadRoots           []string
	Knowledge           string
	Turns               int
	Git                 bool
	PlannerTurns        int
	PlannerTimeout      time.Duration
	PlannerReadBudget   int
	EditorReadBudget    int
	DebuggerToolBudget  int
	EditorTimeout       time.Duration
	EditorTurns         int
	DebuggerTurns       int
	DebuggerTimeout     time.Duration
	DebuggerPolicy      string
	WorkerModels        map[string]string
	Pricing             detection.TokenPricing
	GuestSSH            string
	GuestSSHKey         string
	GuestSSHExclude     string
	GuestSSHKnownHosts  string
	GuestSSHFingerprint string
	GuestSSHInsecure    bool
	GuestSSHTimeout     time.Duration
	Timeout             time.Duration
	CycleTimeout        time.Duration
	SessionTimeout      time.Duration
	ToolIdleTimeout     time.Duration
	Tmux                bool
	Goal                string
	RenderWidth         int
}

// applyDetectLoopLabs fills the loop's lab and guest settings from the
// operator file. Resume paths use it too, because saved manifests predate a lab
// entry or carry an empty guest field.
func applyDetectLoopLabs(opts *detectLoopOptions) error {
	labs, err := detection.LoadLabs(filepath.Join(live.EmpWorkSpace, "detection"))
	if err != nil {
		return err
	}
	lab := labs.ForPlatform(opts.Platform)
	if strings.TrimSpace(opts.Sandbox) == "" {
		opts.Sandbox = lab.URL
	}
	if strings.TrimSpace(opts.GuestSSH) == "" {
		opts.GuestSSH = lab.GuestSSH
	}
	if strings.TrimSpace(opts.GuestSSHKey) == "" {
		opts.GuestSSHKey = lab.GuestSSHKey
	}
	if strings.TrimSpace(opts.GuestSSHExclude) == "" {
		opts.GuestSSHExclude = lab.GuestSSHExclude
	}
	if strings.TrimSpace(opts.GuestSSHKnownHosts) == "" {
		opts.GuestSSHKnownHosts = lab.GuestSSHKnownHosts
	}
	if strings.TrimSpace(opts.GuestSSHFingerprint) == "" {
		opts.GuestSSHFingerprint = lab.GuestSSHFingerprint
	}
	if !opts.GuestSSHInsecure {
		opts.GuestSSHInsecure = lab.GuestSSHInsecure
	}
	return nil
}

// detectLoopWindowTitle gives each loop its own tmux window name. The loop ID
// is the stable identity; values from resume arguments are reduced to a safe
// tmux label instead of being passed through as format syntax.
func detectLoopWindowTitle(loopID string) string {
	label := sanitize.SanitizeOneLine(strings.TrimSpace(loopID))
	label = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, label)
	label = strings.Trim(label, "-.")
	if label == "" {
		label = "loop"
	}
	if len(label) > 48 {
		label = label[:48]
	}
	return "detect " + label
}

func runDetectLoopCommand(cmd *cobra.Command, _ []string) {
	// The console loads operator.env at startup, but a long-lived console
	// must see guest SSH values added for a new loop. The loader never
	// overrides an existing environment variable.
	if loaded, err := live.LoadOperatorEnv(); err != nil {
		logging.Warningf("detect_loop: load operator env: %v", err)
	} else if loaded > 0 {
		logging.Infof("detect_loop: loaded %d operator env values", loaded)
	}
	opts := detectLoopOptions{}
	opts.Module, _ = cmd.Flags().GetString("module")
	opts.ModuleDir, _ = cmd.Flags().GetString("module-dir")
	opts.AgentSourceDir, _ = cmd.Flags().GetString("agent-source-dir")
	opts.Shellcode, _ = cmd.Flags().GetString("shellcode")
	opts.AgentType, _ = cmd.Flags().GetString("agent-type")
	opts.Arch, _ = cmd.Flags().GetString("arch")
	opts.AgentGlibc, _ = cmd.Flags().GetString("agent-glibc")
	opts.AgentDynload, _ = cmd.Flags().GetString("agent-dynload")
	opts.AgentLibc, _ = cmd.Flags().GetString("agent-libc")
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
	opts.Git, _ = cmd.Flags().GetBool("git")
	opts.PlannerTurns, _ = cmd.Flags().GetInt("planner-turns")
	opts.PlannerTimeout, _ = cmd.Flags().GetDuration("planner-timeout")
	opts.PlannerReadBudget, _ = cmd.Flags().GetInt("planner-read-budget")
	opts.EditorReadBudget, _ = cmd.Flags().GetInt("editor-read-budget")
	opts.DebuggerToolBudget, _ = cmd.Flags().GetInt("debugger-tool-budget")
	opts.EditorTimeout, _ = cmd.Flags().GetDuration("editor-timeout")
	opts.EditorTurns, _ = cmd.Flags().GetInt("editor-turns")
	opts.DebuggerTurns, _ = cmd.Flags().GetInt("debugger-turns")
	opts.DebuggerTimeout, _ = cmd.Flags().GetDuration("debugger-timeout")
	opts.DebuggerPolicy, _ = cmd.Flags().GetString("debugger-policy")
	opts.Pricing.InputPerMillion, _ = cmd.Flags().GetFloat64("input-price")
	opts.Pricing.OutputPerMillion, _ = cmd.Flags().GetFloat64("output-price")
	opts.Pricing.CacheReadPerMillion, _ = cmd.Flags().GetFloat64("cache-read-price")
	opts.Pricing.CacheWritePerMillion, _ = cmd.Flags().GetFloat64("cache-write-price")
	opts.WorkerModels, _ = cmd.Flags().GetStringToString("worker-model")
	opts.GuestSSH, _ = cmd.Flags().GetString("guest-ssh")
	opts.GuestSSHKey, _ = cmd.Flags().GetString("guest-ssh-key")
	opts.GuestSSHExclude, _ = cmd.Flags().GetString("guest-ssh-exclude")
	opts.GuestSSHKnownHosts, _ = cmd.Flags().GetString("guest-ssh-known-hosts")
	opts.GuestSSHFingerprint, _ = cmd.Flags().GetString("guest-ssh-fingerprint")
	opts.GuestSSHInsecure, _ = cmd.Flags().GetBool("guest-ssh-insecure")
	opts.GuestSSHTimeout, _ = cmd.Flags().GetDuration("guest-ssh-timeout")
	opts.Timeout, _ = cmd.Flags().GetDuration("timeout")
	opts.CycleTimeout, _ = cmd.Flags().GetDuration("cycle-timeout")
	opts.SessionTimeout, _ = cmd.Flags().GetDuration("session-timeout")
	opts.ToolIdleTimeout, _ = cmd.Flags().GetDuration("tool-idle-timeout")
	opts.Tmux, _ = cmd.Flags().GetBool("tmux")
	opts.Goal, _ = cmd.Flags().GetString("goal")
	if strings.TrimSpace(opts.CC) == "" {
		opts.CC = strings.TrimSpace(live.GetRuntimeConfig().CCAddress)
	}

	if opts.ModuleDir == "" {
		module := strings.TrimSpace(opts.Module)
		if module == "" {
			module = "loader_windows"
		}
		if mod, ok := def.GetModule(module); ok && mod != nil {
			opts.ModuleDir = mod.Path
		}
	}
	if opts.Module == "" && opts.ModuleDir != "" {
		opts.Module = filepath.Base(filepath.Clean(opts.ModuleDir))
	}
	opts.Module = strings.ToLower(strings.TrimSpace(opts.Module))
	if opts.Module == "" {
		opts.Module = "loader_windows"
	}
	if !detection.Covered(opts.Module) {
		logging.Errorf("detect_loop: module must be loader_windows or stager_linux")
		return
	}
	opts.Platform = detection.PlatformForModule(opts.Module)
	if err := applyDetectLoopLabs(&opts); err != nil {
		logging.Errorf("detect_loop: load labs: %v", err)
		return
	}
	if opts.AgentType = strings.ToLower(strings.TrimSpace(opts.AgentType)); opts.AgentType == "" {
		opts.AgentType = "auto"
	}
	if opts.Platform == "linux" {
		switch opts.AgentType {
		case "auto", "linux_so", "linux_shellcode":
			opts.AgentType = "linux_so"
		default:
			logging.Errorf("detect_loop: stager_linux uses agent type linux_so")
			return
		}
	} else {
		switch opts.AgentType {
		case "auto", builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL:
		default:
			logging.Errorf("detect_loop: agent type must be auto, %s, or %s",
				builder.PayloadTypeWindowsExecutable, builder.PayloadTypeWindowsDLL)
			return
		}
	}
	if opts.Arch != "amd64" {
		logging.Errorf("detect_loop: this payload is built for amd64; use --arch amd64")
		return
	}
	switch policy := strings.ToLower(strings.TrimSpace(opts.DebuggerPolicy)); policy {
	case "", "final":
		opts.DebuggerPolicy = "final"
	case "cycle", "off":
		opts.DebuggerPolicy = policy
	default:
		logging.Errorf("detect_loop: debugger policy must be final, cycle, or off")
		return
	}
	if opts.ModuleDir == "" {
		logging.Errorf("detect_loop: pass --module-dir or install %s", opts.Module)
		return
	}
	if info, err := os.Stat(opts.ModuleDir); err != nil || !info.IsDir() {
		logging.Errorf("detect_loop: module directory %q is not readable", opts.ModuleDir)
		return
	}
	if opts.Platform == "linux" {
		if opts.AgentSourceDir == "" {
			opts.AgentSourceDir = detection.DefaultAgentSourceDir(opts.ModuleDir)
		}
		opts.AgentSourceDir = detection.ExpandHomePath(opts.AgentSourceDir)
		if info, err := os.Stat(opts.AgentSourceDir); err != nil || !info.IsDir() {
			logging.Errorf("detect_loop: C agent source directory %q is not readable", opts.AgentSourceDir)
			return
		}
		if len(opts.Producers) > 0 {
			logging.Errorf("detect_loop: stager_linux always uses the shipped malasada producer; remove --producer")
			return
		}
		malasadaDir := detection.LinuxProducerDir(opts.ModuleDir)
		if malasadaDir == "" {
			logging.Errorf("detect_loop: the shipped malasada producer was not found; install the operator kit")
			return
		}
		opts.Producers = []string{"malasada=" + malasadaDir}
	} else {
		if opts.AgentSourceDir != "" {
			logging.Errorf("detect_loop: --agent-source-dir is only used by stager_linux")
			return
		}
		if len(opts.Producers) == 0 {
			for name, dir := range detection.DefaultProducerDirs() {
				opts.Producers = append(opts.Producers, name+"="+dir)
			}
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
	loopStamp := time.Now().UTC().Format("20060102-150405")
	loopID := "loop-" + loopStamp
	logPath := filepath.Join(logDir, "detect-loop-"+loopStamp+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logging.Errorf("detect_loop: open log: %v", err)
		return
	}
	logger := newLoopLogger(logFile)
	logf := logger.printf

	if opts.Tmux {
		window, tmuxErr := cli.TmuxNewPane(detectLoopWindowTitle(loopID), "", "", 0, loopTailCommand(logPath))
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
	prompts := detection.NewOperatorPromptQueue()
	run, err := registerDetectRun(loopID, prompts, logPath, logger)
	if err != nil {
		logging.Errorf("detect_loop: register loop: %v", err)
		logger.close()
		return
	}
	saveLoopManifest(loopID, loopID, 1, "running", opts, run)
	logging.Infof("Detection loop %s started; log: %s", loopID, logPath)
	logging.Warningf("detect_loop: source and build edits execute on this host; review and prompt rules do not contain the model. Use complete isolation.")
	logging.Infof("Manage with: detect_loop list | detect_loop resume %s | detect_loop stop %s | detect_loop prompt %s <instruction>", loopID, loopID, loopID)

	go func() {
		shellcode := strings.TrimSpace(opts.Shellcode)
		if shellcode == "" {
			logf("generating agent shellcode (%s/%s)", opts.AgentType, opts.Arch)
			generated, agentArtifact, producer, agentType, agentUUID, genErr := generateAgentShellcode(opts, logf)
			if genErr != nil {
				logf("shellcode generation failed: %v", genErr)
				run.setError(genErr)
				saveLoopManifest(loopID, loopID, 1, "failed", opts, run)
				run.finish()
				return
			}
			shellcode = generated
			opts.AgentArtifact = agentArtifact
			opts.ShellcodeGenerated = true
			opts.AgentType = agentType
			opts.ShellcodeProducer = producer
			opts.AgentUUID = agentUUID
			opts.Shellcode = generated
			saveLoopManifest(loopID, loopID, 1, "running", opts, run)
			logf("generated %s shellcode: %s", producer, shellcode)
		}
		opts.Shellcode = shellcode
		runDetectLoop(run, opts, shellcode, loopID, 1, 3)
	}()
}

// guestConfig resolves the debugger's sandbox SSH endpoint. The operator must
// opt in with a flag or the environment; there is no implicit default host.
func (opts detectLoopOptions) guestConfig() (*detection.GuestSSHConfig, error) {
	endpoint := envOr(opts.GuestSSH, "EMP3R0R_DETECTION_GUEST_SSH")
	key := envOr(opts.GuestSSHKey, "EMP3R0R_DETECTION_GUEST_SSH_KEY")
	if endpoint == "" && key == "" {
		return nil, nil
	}
	if endpoint == "" || key == "" {
		return nil, fmt.Errorf("guest SSH requires both --guest-ssh user@host:port and --guest-ssh-key")
	}
	user, host, port, err := detection.ParseGuestSSHEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	key = detection.ExpandHomePath(key)
	if info, err := os.Stat(key); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("guest SSH key %q is not readable", key)
	}
	exclude := envOr(opts.GuestSSHExclude, "EMP3R0R_DETECTION_GUEST_SSH_EXCLUDE")
	return &detection.GuestSSHConfig{
		Platform: opts.Platform, Host: host, Port: port, User: user, KeyPath: key,
		KnownHostsPath: detection.ExpandHomePath(opts.GuestSSHKnownHosts),
		Fingerprint:    strings.TrimSpace(opts.GuestSSHFingerprint),
		Insecure:       opts.GuestSSHInsecure,
		ExcludePath:    exclude,
		Timeout:        opts.GuestSSHTimeout,
	}, nil
}

func envOr(value, key string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(os.Getenv(key))
}

// parseGuestSSHEndpoint keeps the operator test surface stable; the parser
// itself lives in the detection package so MCP uses the same rules.
func parseGuestSSHEndpoint(value string) (user, host string, port int, err error) {
	return detection.ParseGuestSSHEndpoint(value)
}

func generateAgentShellcode(opts detectLoopOptions, logf func(string, ...any)) (shellcode, agentArtifact, producer, agentType, agentUUID string, err error) {
	if opts.Platform == "linux" {
		return generateLinuxAgentShellcode(opts, logf)
	}
	producers, err := detection.ParseProducerDirs(opts.Producers)
	if err != nil {
		return "", "", "", "", "", err
	}
	producer, producerDir, agentType := chooseShellcodeProducer(producers, opts.AgentType)
	if producer == "" {
		return "", "", "", "", "", fmt.Errorf("no shellcode producer configured for agent type %s; pass --shellcode or add a matching --producer entry", opts.AgentType)
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
		return "", "", "", "", "", err
	}
	if result == nil || strings.TrimSpace(result.OutputFile) == "" {
		return "", "", "", "", "", fmt.Errorf("agent build produced no artifact")
	}

	flags := map[string]string{"output": result.OutputFile + "." + producerShellcodeExt(producer)}
	switch producer {
	case "crystal_pack":
		flags["dll"] = result.OutputFile
	case "donut":
		flags["input"] = result.OutputFile
	default:
		return "", "", "", "", "", fmt.Errorf("producer %q has no agent wrapper", producer)
	}
	buildLog, err := modules.BuildLocalModuleAt(producerDir, producer, flags)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("%s producer: %w\n%s", producer, err, lastLogLines(buildLog, 20))
	}
	payloads := detection.ParseGeneratedPayloads(buildLog)
	if len(payloads) == 0 {
		return "", "", "", "", "", fmt.Errorf("%s producer did not report a generated payload", producer)
	}
	return payloads[len(payloads)-1].Path, result.OutputFile, producer, agentType, result.AgentUUID, nil
}

// generateLinuxAgentShellcode builds the C agent PIC that stager_linux embeds.
// The source tree is the same writable c_agent root the model edits.
func generateLinuxAgentShellcode(opts detectLoopOptions, logf func(string, ...any)) (shellcode, agentArtifact, producer, agentType, agentUUID string, err error) {
	sourceDir := strings.TrimSpace(opts.AgentSourceDir)
	if sourceDir == "" {
		sourceDir = detection.DefaultAgentSourceDir(opts.ModuleDir)
	}
	agentCfg := builder.AgentConfig{IsStager: true}
	if strings.TrimSpace(opts.CC) != "" {
		cc := strings.TrimSpace(opts.CC)
		agentCfg.CCAddress = &cc
	}
	libc := strings.TrimSpace(opts.AgentLibc)
	if libc == "" {
		libc = "glibc"
	}
	glibc := strings.TrimSpace(opts.AgentGlibc)
	if glibc == "" {
		glibc = "2.17"
	}
	dynload := strings.TrimSpace(opts.AgentDynload)
	if dynload == "" {
		dynload = "auto"
	}
	dynload = builder.CAgentDynloadForLibc(libc, dynload, false)
	providers := builder.CAgentProviders{
		Format: "so", Arch: opts.Arch, Libc: libc,
		Glibc: glibc, Dynload: dynload,
	}
	logf("C agent source: %s", sourceDir)
	generationMu.Lock()
	result, err := builder.GenerateCAgentWorkflowAt(sourceDir, agentCfg, providers, client.SignAgent)
	if err != nil {
		logf("signed C agent generation failed (%v); building without a C2 signature", err)
		result, err = builder.GenerateCAgentWorkflowAt(sourceDir, agentCfg, providers, nil)
	}
	generationMu.Unlock()
	if err != nil {
		return "", "", "", "", "", err
	}
	if result == nil || strings.TrimSpace(result.OutputFile) == "" {
		return "", "", "", "", "", fmt.Errorf("c agent build produced no artifact")
	}
	pic, err := buildMalasadaShellcode(opts, result.OutputFile, result.AgentUUID, logf)
	if err != nil {
		return "", "", "", "", "", err
	}
	return pic, result.OutputFile, "malasada", "linux_so", result.AgentUUID, nil
}

// buildMalasadaShellcode runs the installed malasada module on a C agent
// shared object. The module builds from its editable source, so a source edit
// changes the next blob.
func buildMalasadaShellcode(opts detectLoopOptions, soPath, agentUUID string, logf func(string, ...any)) (string, error) {
	dir := detection.LinuxProducerDir(opts.ModuleDir)
	if dir == "" {
		return "", fmt.Errorf("the shipped malasada producer was not found; install the operator kit")
	}
	outDir := filepath.Join(live.EmpWorkSpace, "detection", "shellcode")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("create shellcode directory: %w", err)
	}
	output := filepath.Join(outDir, "malasada-"+strings.TrimSpace(agentUUID)+".bin")
	logf("malasada producer: %s -> %s", soPath, output)
	buildLog, err := modules.BuildLocalModuleAt(dir, "malasada", map[string]string{
		"input": soPath, "output": output, "call-export": "main", "compress": "on",
	})
	if err != nil {
		return "", fmt.Errorf("malasada producer: %w\n%s", err, lastLogLines(buildLog, 20))
	}
	payloads := detection.ParseGeneratedPayloads(buildLog)
	if len(payloads) == 0 {
		return "", fmt.Errorf("malasada producer did not report a generated payload")
	}
	return payloads[len(payloads)-1].Path, nil
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
		if dir := strings.TrimSpace(producers["crystal_pack"]); dir != "" && modules.CrystalPackAvailable(dir) {
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
	if dir := strings.TrimSpace(producers["crystal_pack"]); dir != "" && modules.CrystalPackAvailable(dir) {
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

func lastLogLines(log string, n int) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// loopLogger serializes progress and class-tagged lines through one writer
// goroutine. Callers never hold a lock while the log file is written.
type loopLogger struct {
	w         io.Writer
	entries   chan logEntry
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

type logEntry struct {
	class    logging.Class
	progress bool
	format   string
	args     []any
}

func newLoopLogger(w io.Writer) *loopLogger {
	logger := &loopLogger{
		w: w, entries: make(chan logEntry, 256),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go logger.run()
	return logger
}

func (l *loopLogger) run() {
	defer close(l.done)
	for {
		select {
		case entry := <-l.entries:
			l.write(entry)
		case <-l.stop:
			for {
				select {
				case entry := <-l.entries:
					l.write(entry)
				default:
					return
				}
			}
		}
	}
}

func (l *loopLogger) write(entry logEntry) {
	if entry.progress {
		line := sanitize.SanitizeText(fmt.Sprintf(entry.format, entry.args...))
		fmt.Fprintf(l.w, "%s %s\n", time.Now().Format("15:04:05"), line)
		return
	}
	logging.ClassfToPlain(l.w, entry.class, entry.format, entry.args...)
}

func (l *loopLogger) close() {
	l.closeOnce.Do(func() {
		close(l.stop)
		<-l.done
		if closer, ok := l.w.(io.Closer); ok {
			_ = closer.Close()
		}
	})
}

func (l *loopLogger) enqueue(entry logEntry) {
	select {
	case l.entries <- entry:
	case <-l.stop:
	}
}

func (l *loopLogger) printf(format string, args ...any) {
	l.enqueue(logEntry{progress: true, format: format, args: args})
}

func (l *loopLogger) logf(class logging.Class, format string, args ...any) {
	l.enqueue(logEntry{class: class, format: format, args: args})
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

// loopTailCommand tails the plain log and colors its class tags in the tmux
// pane. The file on disk stays free of ANSI escapes.
func loopTailCommand(path string) string {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return "tail -F " + shellQuotePath(path)
	}
	const colorizer = `{
		tag = $2
		color = ""
		if (tag == "[thinking]") color = "\033[2m"
		else if (tag == "[model]") color = "\033[36m"
		else if (tag == "[tool]") color = "\033[93m"
		else if (tag == "[result]") color = "\033[32m"
		else if (tag == "[build]") color = "\033[94m"
		else if (tag == "[cycle]") color = "\033[1;35m"
		else if (tag == "[edit]") color = "\033[96m"
		else if (tag == "[answer]") color = "\033[1;92m"
		else if (tag == "[report]") color = "\033[1;97m"
		else if (tag == "[warn]") color = "\033[1;33m"
		else if (tag == "[error]") color = "\033[1;31m"
		else if (tag == "[progress]") color = "\033[90m"
		if (color != "") printf "%s%s\033[0m\n", color, $0
		else print
	}`
	return "tail -F " + shellQuotePath(path) + " | awk '" + colorizer + "'"
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

// knowledgeSyncOptions is the resolved knowledge-sync request. The parent and
// its child process read the flags through this one type so both write the same
// cache.
type knowledgeSyncOptions struct {
	URL      string
	DB       string
	Notebook string
	Content  bool
}

func readKnowledgeSyncOptions(cmd *cobra.Command) knowledgeSyncOptions {
	opts := knowledgeSyncOptions{}
	opts.URL, _ = cmd.Flags().GetString("url")
	opts.DB, _ = cmd.Flags().GetString("db")
	opts.Notebook, _ = cmd.Flags().GetString("notebook")
	opts.Content, _ = cmd.Flags().GetBool("content")
	if opts.DB == "" {
		opts.DB = defaultKnowledgePath()
	}
	return opts
}

func (opts knowledgeSyncOptions) args() []string {
	args := []string{"knowledge-sync", "--url", opts.URL, "--db", opts.DB}
	if opts.Notebook != "" {
		args = append(args, "--notebook", opts.Notebook)
	}
	if opts.Content {
		args = append(args, "--content")
	}
	return args
}

func runKnowledgeSync(cmd *cobra.Command) {
	if os.Getenv(operatorSubprocessEnv) == "1" {
		// The console parent captures this process's stdout and mirrors it to
		// the output pane. Send logger messages there as well as to the file.
		logging.AddWriter(os.Stdout)
	}
	opts := readKnowledgeSyncOptions(cmd)
	db, err := detection.OpenKnowledgeDB(opts.DB, true)
	if err != nil {
		logging.Errorf("knowledge-sync: %v", err)
		return
	}
	defer func() { _ = db.Close() }()
	stats, err := detection.SyncKnowledge(context.Background(), db, detection.KnowledgeSyncOptions{
		URL: opts.URL, Notebook: opts.Notebook, Content: opts.Content,
		Logf: func(line string) { fmt.Println(line) },
	})
	if err != nil {
		logging.Errorf("knowledge-sync: %v", err)
		return
	}
	logging.Successf("Knowledge cache %s: %d summaries, %d contents from %d notebooks",
		opts.DB, stats.Summaries, stats.Contents, stats.Notebooks)
}

// knowledgeSyncArgs rebuilds the child's argv from the parsed command. The
// database path is resolved here so the child writes the same cache.
func knowledgeSyncArgs(cmd *cobra.Command) []string {
	return readKnowledgeSyncOptions(cmd).args()
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
