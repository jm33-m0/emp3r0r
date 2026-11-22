package detection

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// addLinuxFindings derives the Linux-specific actionable findings from Tracee
// events and Falco alerts. The Windows rules below it stay in place: a trace
// has one platform and the queries are disjoint.
func (t *TelemetryDB) addLinuxFindings(ctx context.Context, traceID int64, add func(severity, rule, indicator, detail string)) {
	// Falco is the stable, named rule surface. A rule hit is actionable even
	// if the underlying Tracee event is also present.
	falco, err := t.rows(ctx, `SELECT event, severity, pid, path, image, command, attrs FROM events
		WHERE trace_pk = ? AND provider = 'falco' AND signal = 'signal' ORDER BY id LIMIT 200`, traceID)
	if err == nil {
		seen := map[string]struct{}{}
		for _, row := range falco {
			rule := strings.TrimSpace(row.string("event"))
			if rule == "" {
				continue
			}
			if _, ok := seen[rule]; ok {
				continue
			}
			seen[rule] = struct{}{}
			severity := row.string("severity")
			if severity == "" {
				severity = "medium"
			}
			detail := fmt.Sprintf("Falco rule %q fired for pid %d", rule, row.int("pid"))
			if path := row.string("path"); path != "" {
				detail += " path=" + path
			}
			if command := row.string("command"); command != "" {
				detail += " command=" + command
			}
			add(severity, "falco/"+rule, rule, detail)
		}
	}

	// memfd and ptrace are the Linux equivalents of anonymous executable
	// memory and cross-process injection.
	memory, err := t.rows(ctx, `SELECT event, operation, pid, target_pid, protection, size, path, image
		FROM events WHERE trace_pk = ? AND category = 'memory'
		AND signal IN ('signal', 'unattributed')
		AND payload_role IN ('payload', 'payload-child') ORDER BY id LIMIT 200`, traceID)
	if err == nil {
		seen := map[string]struct{}{}
		for _, row := range memory {
			operation := strings.ToLower(row.string("operation"))
			event := strings.ToLower(row.string("event"))
			rule, indicator := "", ""
			switch {
			case strings.Contains(operation, "ptrace") || strings.Contains(event, "ptrace"):
				rule, indicator = "telemetry/ptrace", "ptrace"
			case strings.Contains(operation, "create") || strings.Contains(event, "memfd"):
				rule, indicator = "telemetry/memfd", "memfd_create"
			case operation == "write" || operation == "read":
				rule, indicator = "telemetry/process-vm", "process_vm_readv/writev"
			case operation == "protect" || operation == "map":
				if !protectedExecutable(row.string("protection")) {
					continue
				}
				rule, indicator = "telemetry/exec-memory", "mmap/mprotect PROT_EXEC"
			default:
				continue
			}
			severity := "high"
			if rule == "telemetry/exec-memory" {
				severity = "medium"
			}
			key := rule + "|" + indicator + "|" + strconv.FormatInt(row.int("pid"), 10)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			detail := fmt.Sprintf("%s observed %s pid=%d", rule, row.string("event"), row.int("pid"))
			if target := row.int("target_pid"); target != 0 {
				detail += fmt.Sprintf(" target_pid=%d", target)
			}
			if size := row.int("size"); size > 0 {
				detail += fmt.Sprintf(" size=%d", size)
			}
			if protection := row.string("protection"); protection != "" {
				detail += " protection=" + protection
			}
			add(severity, rule, indicator, detail)
		}
	}

	kernel, err := t.rows(ctx, `SELECT event, operation, pid, path, image FROM events
		WHERE trace_pk = ? AND category = 'kernel' ORDER BY id LIMIT 20`, traceID)
	if err == nil {
		for _, row := range kernel {
			add("critical", "telemetry/kernel-module", "kernel module load",
				fmt.Sprintf("payload loaded or removed a kernel module: %s pid=%d", row.string("event"), row.int("pid")))
			break
		}
	}
	namespace, err := t.rows(ctx, `SELECT event, operation, pid FROM events
		WHERE trace_pk = ? AND category = 'namespace' ORDER BY id LIMIT 20`, traceID)
	if err == nil {
		for _, row := range namespace {
			add("high", "telemetry/namespace", row.string("event"),
				fmt.Sprintf("payload changed its namespace or mount view: %s pid=%d", row.string("event"), row.int("pid")))
			break
		}
	}

	// A payload that executes from a writable path is a dropped second stage,
	// which is a distinct finding from an ordinary child process.
	execs, err := t.rows(ctx, `SELECT event, pid, image, path, command FROM events
		WHERE trace_pk = ? AND category = 'process' AND operation = 'create'
		AND payload_role IN ('payload', 'payload-child') ORDER BY id LIMIT 200`, traceID)
	if err == nil {
		seen := map[string]struct{}{}
		for _, row := range execs {
			path := firstNonEmpty(row.string("path"), row.string("image"))
			if !writableExecPath(path) {
				continue
			}
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			add("high", "telemetry/writable-exec", path,
				"payload executed a file from a writable path: "+path)
		}
	}
}

func protectedExecutable(protection string) bool {
	protection = strings.ToLower(strings.TrimSpace(protection))
	if protection == "" {
		return false
	}
	if strings.Contains(protection, "exec") || strings.Contains(protection, "x") {
		if strings.Contains(protection, "prot_exec") || protection == "x" || protection == "rx" || protection == "rwx" {
			return true
		}
	}
	value, err := strconv.ParseInt(protection, 0, 64)
	return err == nil && value&0x4 != 0
}

func writableExecPath(path string) bool {
	path = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), `\`, "/"))
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
