package detection

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PenguinBox is the Linux sandbox. It implements the LitterBox HTTP contract
// but returns a Tracee event stream and Falco alerts instead of RedEdr.
type penguinBoxRun struct {
	RunID         string    `json:"run_id"`
	MD5           string    `json:"md5"`
	SHA256        string    `json:"sha256"`
	Name          string    `json:"name"`
	Artifact      string    `json:"artifact"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	PayloadPID    int64     `json:"payload_pid"`
	ExitCode      int       `json:"exit_code"`
	TimedOut      bool      `json:"timed_out"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	DurationMS    int64     `json:"duration_ms"`
	Warnings      []string  `json:"warnings"`
	LogTail       string    `json:"log_tail"`
	Error         string    `json:"error"`
}

type penguinBoxCollectorCoverage struct {
	Events int    `json:"events"`
	Alerts int    `json:"alerts"`
	Error  string `json:"error"`
}

type penguinBoxCoverage struct {
	Tracee   penguinBoxCollectorCoverage `json:"tracee"`
	Falco    penguinBoxCollectorCoverage `json:"falco"`
	Expected []string                    `json:"expected"`
	Missing  []string                    `json:"missing"`
}

// Getter that accepts both the LitterBox-style wrapper and a bare PenguinBox
// dynamic result: /api/results/dynamic returns the wrapper, while a stored
// result file may carry only the result object.
func penguinBoxResult(value any) map[string]any {
	top, _ := value.(map[string]any)
	if top == nil {
		return nil
	}
	if nested, ok := top["results"].(map[string]any); ok {
		return nested
	}
	if _, ok := top["run"].(map[string]any); ok {
		return top
	}
	if _, ok := top["findings"].(map[string]any); ok {
		return top
	}
	return nil
}

func isPenguinBoxDynamic(value any) bool {
	result := penguinBoxResult(value)
	if result == nil {
		return false
	}
	_, hasRun := result["run"].(map[string]any)
	findings, hasFindings := result["findings"].(map[string]any)
	if !hasRun && !hasFindings {
		return false
	}
	if hasFindings {
		if _, ok := findings["events"]; ok {
			return true
		}
	}
	return hasRun
}

// parsePenguinBoxDynamic turns one PenguinBox dynamic result into normalized
// Tracee and Falco events. The parser never trusts the container fields for
// attribution: the run's payload_pid is the identity the guest measured.
func parsePenguinBoxDynamic(data []byte) (parsedTelemetry, bool, error) {
	value, err := decodeJSON(data)
	if err != nil {
		return parsedTelemetry{}, false, nil
	}
	if !isPenguinBoxDynamic(value) {
		return parsedTelemetry{}, false, nil
	}
	result := penguinBoxResult(value)
	rawRun, _ := json.Marshal(result["run"])
	var run penguinBoxRun
	_ = json.Unmarshal(rawRun, &run)
	rawCoverage, _ := json.Marshal(result["coverage"])
	var coverage penguinBoxCoverage
	_ = json.Unmarshal(rawCoverage, &coverage)

	parsed := parsedTelemetry{
		Source:   "penguinbox",
		Platform: platformLinux,
		Meta:     map[string]any{"platform": platformLinux},
	}
	if result["run"] != nil {
		parsed.Meta["run"] = result["run"]
	}
	if result["coverage"] != nil {
		parsed.Meta["coverage"] = result["coverage"]
	}
	if len(run.Warnings) > 0 {
		parsed.Meta["warnings"] = run.Warnings
	}
	if run.Error != "" {
		parsed.Meta["run_error"] = run.Error
	}
	parsed.ExternalID = strings.TrimSpace(run.RunID)
	if parsed.ExternalID == "" && run.SHA256 != "" {
		parsed.ExternalID = "sha256:" + run.SHA256
	}

	findings, _ := result["findings"].(map[string]any)
	rawEvents, _ := findings["events"].([]any)
	hostPIDs := penguinBoxHostPIDMap(rawEvents)
	deliveredTracee := false
	deliveredFalco := false
	seen := map[string]struct{}{}
	for _, raw := range rawEvents {
		object, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		collector := strings.ToLower(strings.TrimSpace(jsonString(object["collector"])))
		switch {
		case collector == "falco" || isFalcoEvent(object):
			events := normalizeFalcoEvent(object)
			if len(events) > 0 {
				deliveredFalco = true
			}
			for i := range events {
				events[i].PID = penguinBoxGuestPID(hostPIDs, events[i].PID)
				events[i].ActorPID = events[i].PID
				events[i].ParentPID = penguinBoxGuestPID(hostPIDs, events[i].ParentPID)
			}
			for _, event := range events {
				if _, ok := seen[event.EventKey]; ok {
					continue
				}
				if len(parsed.Events) >= maxTelemetryEvents {
					return parsedTelemetry{}, true, fmt.Errorf("telemetry exceeds %d events", maxTelemetryEvents)
				}
				seen[event.EventKey] = struct{}{}
				parsed.Events = append(parsed.Events, event)
			}
		default:
			if !isTraceeEvent(object) {
				continue
			}
			event := normalizeTraceeEvent(object)
			if event.EventKey != "" {
				if _, ok := seen[event.EventKey]; ok {
					continue
				}
				seen[event.EventKey] = struct{}{}
			}
			if len(parsed.Events) >= maxTelemetryEvents {
				return parsedTelemetry{}, true, fmt.Errorf("telemetry exceeds %d events", maxTelemetryEvents)
			}
			deliveredTracee = true
			parsed.Events = append(parsed.Events, event)
		}
	}
	if len(parsed.Events) == 0 {
		return parsedTelemetry{}, true, errors.New("PenguinBox dynamic result has no Tracee or Falco events")
	}
	payloadPID := int64(0)
	if guestPID, ok := hostPIDs[run.PayloadPID]; ok {
		payloadPID = guestPID
	}
	parsed.PayloadPID, parsed.PayloadImage = penguinBoxPayloadIdentity(parsed.Events, payloadPID)
	parsed.Events = penguinBoxTrimStartupEvents(parsed.Events, parsed.PayloadPID)
	parsed.Attribution = "container"
	if parsed.PayloadImage == "" {
		parsed.PayloadImage = filepath.Base(strings.TrimSpace(run.Artifact))
	}
	parsed.Coverage = penguinBoxTelemetryCoverage(coverage, deliveredTracee, deliveredFalco)
	for _, event := range parsed.Events {
		if event.TS.IsZero() {
			continue
		}
		if parsed.First.IsZero() || event.TS.Before(parsed.First) {
			parsed.First = event.TS
		}
		if event.TS.After(parsed.Last) {
			parsed.Last = event.TS
		}
	}
	if parsed.First.IsZero() {
		parsed.First = run.StartedAt
	}
	if parsed.Last.IsZero() {
		parsed.Last = run.FinishedAt
	}
	return parsed, true, nil
}

// penguinBoxHostPIDMap maps Tracee host PID to the PID the guest sees. Falco
// reports host PIDs while Tracee processId is namespace-local, so a role check
// must translate before attribution.
func penguinBoxHostPIDMap(rawEvents []any) map[int64]int64 {
	objects := make([]map[string]any, 0, len(rawEvents))
	for _, raw := range rawEvents {
		if object, ok := raw.(map[string]any); ok {
			objects = append(objects, object)
		}
	}
	return penguinBoxHostPIDMapObjects(objects)
}

func penguinBoxHostPIDMapObjects(objects []map[string]any) map[int64]int64 {
	out := map[int64]int64{}
	for _, object := range objects {
		host := firstInt(object, "hostProcessId")
		pid := firstInt(object, "processId")
		if host != 0 && pid != 0 && host != pid {
			out[host] = pid
		}
	}
	return out
}

func penguinBoxGuestPID(mapping map[int64]int64, host int64) int64 {
	if guest, ok := mapping[host]; ok {
		return guest
	}
	return host
}

// penguinBoxTrimStartupEvents drops the container runtime's own pre-exec work
// for the payload PID. crun and the payload can share PID 1 in a PID namespace,
// so events before the payload exec would otherwise be attributed to it.
func penguinBoxTrimStartupEvents(events []telemetryEvent, payloadPID int64) []telemetryEvent {
	if payloadPID == 0 {
		return events
	}
	var start time.Time
	for _, event := range events {
		if event.PID == payloadPID && event.Operation == "create" && event.Event == "sched_process_exec" {
			start = event.TS
			break
		}
	}
	if start.IsZero() {
		return events
	}
	out := events[:0]
	for _, event := range events {
		if event.PID == payloadPID && event.TS.Before(start) && event.Provider != "falco" &&
			(event.Operation != "create" || event.Event != "sched_process_exec") {
			continue
		}
		out = append(out, event)
	}
	return out
}

// penguinBoxPayloadIdentity finds the payload process inside the guest. The
// run's payload_pid comes from podman inspect and is a host PID; callers map it
// through Tracee's hostProcessId/processId pairs before calling this function.
// The container entrypoint is the payload itself, so the first exec of the
// payload path is the fallback identity.
func penguinBoxPayloadIdentity(events []telemetryEvent, payloadPID int64) (int64, string) {
	for _, event := range events {
		if payloadPID != 0 && event.PID == payloadPID {
			return event.PID, event.Image
		}
	}
	for _, event := range events {
		if event.Event != "sched_process_exec" || event.PID == 0 {
			continue
		}
		if process := strings.ToLower(event.Process); process != "crun" && process != "conmon" && process != "runc" {
			return event.PID, firstNonEmpty(event.Image, event.Process)
		}
	}
	for _, event := range events {
		if event.Category != "process" || event.Operation != "create" {
			continue
		}
		path := strings.ToLower(strings.ReplaceAll(firstNonEmpty(event.Path, event.Image), `\`, "/"))
		if path == "/payload" || strings.HasSuffix(path, "/payload") {
			return event.PID, firstNonEmpty(event.Image, path)
		}
	}
	for _, event := range events {
		if event.PID == 0 || event.Category == "falco" {
			continue
		}
		process := strings.ToLower(event.Process)
		switch process {
		case "conmon", "crun", "runc", "podman", "pause":
			continue
		}
		return event.PID, event.Image
	}
	return 0, ""
}

func penguinBoxTelemetryCoverage(coverage penguinBoxCoverage, tracee, falco bool) TelemetryCoverage {
	out := TelemetryCoverage{
		Expected:  append([]string(nil), coverage.Expected...),
		Missing:   append([]string(nil), coverage.Missing...),
		Analyzers: map[string]string{"tracee": "ok", "falco": "ok"},
	}
	if len(out.Expected) == 0 {
		out.Expected = []string{"tracee", "falco"}
	}
	if tracee {
		out.Delivered = append(out.Delivered, "tracee")
	}
	if falco {
		out.Delivered = append(out.Delivered, "falco")
	}
	if coverage.Tracee.Error != "" {
		out.Missing = append(out.Missing, "tracee: "+coverage.Tracee.Error)
		out.Analyzers["tracee"] = "failed: " + clip(coverage.Tracee.Error, 160)
	}
	if coverage.Falco.Error != "" {
		out.Missing = append(out.Missing, "falco: "+coverage.Falco.Error)
		out.Analyzers["falco"] = "failed: " + clip(coverage.Falco.Error, 160)
	}
	for _, want := range out.Expected {
		found := false
		for _, got := range out.Delivered {
			if strings.EqualFold(want, got) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		already := false
		for _, missing := range out.Missing {
			if strings.EqualFold(missing, want) {
				already = true
				break
			}
		}
		if !already {
			out.Missing = append(out.Missing, want)
		}
	}
	out.Missing = uniqueStrings(out.Missing)
	return sanitizeTelemetryCoverage(out)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func isFalcoEvent(object map[string]any) bool {
	_, hasRule := object["rule"]
	_, hasPriority := object["priority"]
	_, hasFields := object["output_fields"]
	return hasRule && (hasPriority || hasFields)
}

func isTraceeEvent(object map[string]any) bool {
	_, hasEvent := object["eventName"]
	_, hasContainer := object["containerId"]
	_, hasProcess := object["processId"]
	return hasEvent || (hasContainer && hasProcess)
}

func falcoSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "emergency", "alert", "critical":
		return "critical"
	case "error":
		return "high"
	case "warning":
		return "high"
	case "notice":
		return "medium"
	case "informational", "info", "debug":
		return "info"
	}
	return normalizeSeverity(value)
}

// normalizeFalcoEvent maps one Falco JSON alert into the common event model.
// The rule name is the stable detection vocabulary the model edits against.
func normalizeFalcoEvent(object map[string]any) []telemetryEvent {
	fields, _ := object["output_fields"].(map[string]any)
	rule := strings.TrimSpace(jsonString(object["rule"]))
	if rule == "" {
		rule = "Falco alert"
	}
	priority := falcoSeverity(jsonString(object["priority"]))
	pid := firstInt(fields, "proc.pid")
	ppid := firstInt(fields, "proc.ppid")
	image := firstString(fields, "proc.exe")
	process := firstString(fields, "proc.name")
	command := firstString(fields, "proc.cmdline")
	path := firstString(fields, "fd.name", "evt.arg.path")
	evtType := firstString(fields, "evt.type")
	category, operation := falcoCategory(rule, evtType, path)
	event := telemetryEvent{
		Type:      "falco",
		Source:    "penguinbox",
		Event:     rule,
		Provider:  "falco",
		EventKey:  telemetryObjectKey(encodeObject(object), ""),
		PID:       pid,
		ActorPID:  pid,
		ParentPID: ppid,
		Process:   process,
		Image:     image,
		Path:      path,
		Command:   command,
		Category:  category,
		Operation: operation,
		Severity:  priority,
		Signal:    "signal",
		Attrs:     encodeObject(object),
		TS:        falcoTime(object),
	}
	if event.EventKey == "" {
		event.EventKey = telemetryObjectKey(event.Attrs, "")
	}
	return []telemetryEvent{event}
}

func falcoCategory(rule, evtType, path string) (string, string) {
	evtType = strings.ToLower(strings.TrimSpace(evtType))
	path = strings.ToLower(strings.TrimSpace(path))
	switch evtType {
	case "mmap", "mprotect", "mremap", "memfd_create", "process_vm_readv",
		"process_vm_writev", "ptrace":
		return "memory", traceeMemoryOperation(evtType)
	case "open", "openat", "openat2", "creat", "unlink", "unlinkat",
		"rename", "renameat", "renameat2", "truncate", "ftruncate",
		"chmod", "fchmod", "fchmodat":
		if strings.Contains(path, "/proc/") && strings.HasSuffix(path, "/mem") {
			return "memory", "write"
		}
		if strings.Contains(path, "/proc/") && strings.HasSuffix(path, "/maps") {
			return "memory", "map"
		}
		return "file", "open"
	case "connect", "listen", "socket", "accept", "bind", "security_socket_connect":
		return "network", "connect"
	case "execve", "execveat", "sched_process_exec":
		return "process", "create"
	case "setns", "unshare", "mount", "umount2", "pivot_root":
		return "namespace", "change"
	case "init_module", "finit_module", "delete_module", "bpf", "kexec_load", "kexec_file_load":
		return "kernel", "module"
	}
	// Fallback for alerts without evt.type. Use words that identify a behavior,
	// not generic substrings: "executable" is not an exec event.
	lower := strings.ToLower(rule)
	switch {
	case strings.Contains(lower, "memfd"), strings.Contains(lower, "ptrace"),
		strings.Contains(lower, "proc maps"), strings.Contains(lower, "process_vm"),
		strings.Contains(lower, "mmap"), strings.Contains(lower, "mprotect"):
		op := "map"
		if strings.Contains(lower, "memfd") {
			op = "create"
		} else if strings.Contains(lower, "ptrace") {
			op = "ptrace"
		} else if strings.Contains(lower, "mprotect") {
			op = "protect"
		}
		return "memory", op
	case strings.Contains(lower, "connect"), strings.Contains(lower, "network"),
		strings.Contains(lower, "socket"):
		return "network", "connect"
	case strings.Contains(lower, "execve"), strings.Contains(lower, "shell"),
		strings.Contains(lower, "spawned"), strings.Contains(lower, "writable"):
		return "process", "create"
	case strings.Contains(lower, "module"), strings.Contains(lower, "kernel"),
		strings.Contains(lower, "bpf"), strings.Contains(lower, "kexec"):
		return "kernel", "module"
	case strings.Contains(lower, "namespace"), strings.Contains(lower, "mount"),
		strings.Contains(lower, "unshare"), strings.Contains(lower, "setns"):
		return "namespace", "change"
	case strings.Contains(lower, "file"), strings.Contains(lower, "open"),
		strings.Contains(lower, "write"), strings.Contains(lower, "read"):
		return "file", "open"
	}
	return "falco", "alert"
}

func falcoTime(object map[string]any) time.Time {
	raw := jsonString(object["time"])
	if raw == "" {
		return telemetryTime(object)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UTC()
	}
	return telemetryTime(object)
}

// normalizeTraceeEvent maps one Tracee JSON event into the common event model.
// Tracee event names are the syscall or LSM hook; args carry the path, address,
// and flags the finding rules use.
func normalizeTraceeEvent(object map[string]any) telemetryEvent {
	eventName := strings.TrimSpace(jsonString(object["eventName"]))
	pid := firstInt(object, "processId")
	tid := firstInt(object, "threadId")
	ppid := firstInt(object, "parentProcessId")
	process := firstString(object, "processName")
	event := telemetryEvent{
		Type:      "tracee",
		Source:    "penguinbox",
		Event:     eventName,
		Provider:  "tracee",
		EventID:   firstInt(object, "eventId"),
		PID:       pid,
		ActorPID:  pid,
		TID:       tid,
		ParentPID: ppid,
		Process:   process,
		Image:     process,
		Category:  "other",
		Operation: eventName,
		Attrs:     encodeObject(object),
		TS:        traceeTime(object),
		EventKey:  telemetryObjectKey(encodeObject(object), ""),
	}
	switch strings.ToLower(eventName) {
	case "execve", "execveat", "sched_process_exec":
		event.ActorPID = ppid
		path := traceeArg(object, "pathname", "filename", "argv")
		if path == "" {
			path = traceeArg(object, "argv")
		}
		event.Category, event.Operation = "process", "create"
		event.Path = path
		event.Image = firstNonEmpty(path, process)
		event.Command = traceeArg(object, "argv")
	case "open", "openat", "openat2", "creat", "security_file_open", "magic_write", "write", "unlink", "unlinkat", "rename", "renameat":
		event.Category = "file"
		event.Path = traceeArg(object, "pathname", "filename", "path", "name")
		event.Operation = traceeFileOperation(eventName, object)
	case "connect", "accept", "bind", "socket":
		event.Category = "network"
		event.Operation = "connect"
		family, addr, port := traceeSocket(object)
		if family == "AF_UNIX" {
			event.Category = "ipc"
		}
		event.DstAddr, event.DstPort = addr, port
		event.Proto = firstNonEmpty(traceeArg(object, "protocol", "sock_domain"), family)
	case "mmap", "mprotect", "mremap", "memfd_create", "process_vm_readv", "process_vm_writev", "ptrace":
		event.Category = "memory"
		event.Operation = traceeMemoryOperation(eventName)
		event.Address = traceeArgInt(object, "addr", "address")
		event.Size = traceeArgInt(object, "length", "size")
		event.Protection = traceeArg(object, "prot", "protection")
		event.TargetPID = traceeArgInt(object, "pid", "target_pid")
	case "init_module", "finit_module", "delete_module":
		event.Category, event.Operation = "kernel", "module"
	case "setns", "unshare", "mount", "umount2", "pivot_root":
		event.Category, event.Operation = "namespace", "change"
	case "kill", "tgkill":
		event.Category, event.Operation = "process", "signal"
	case "security_socket_connect":
		event.Category, event.Operation = "network", "connect"
		family, addr, port := traceeSocket(object)
		if family == "AF_UNIX" {
			event.Category = "ipc"
		}
		event.DstAddr, event.DstPort = addr, port
		event.Proto = firstNonEmpty(traceeArg(object, "sock_domain", "protocol"), family)
	case "security_task_kill":
		event.Category, event.Operation = "process", "signal"
	}
	if event.Path == "" {
		event.Path = traceeArg(object, "pathname", "filename", "path")
	}
	return event
}

func traceeFileOperation(name string, object map[string]any) string {
	switch strings.ToLower(name) {
	case "magic_write", "write":
		return "write"
	case "unlink", "unlinkat":
		return "delete"
	case "rename", "renameat":
		return "rename"
	}
	flags := traceeArgInt(object, "flags")
	if flags&0x1 != 0 || flags&0x2 != 0 || flags&0x40 != 0 || flags&0x200 != 0 {
		return "write"
	}
	return "open"
}

func traceeMemoryOperation(name string) string {
	switch strings.ToLower(name) {
	case "mmap", "mremap":
		return "map"
	case "mprotect":
		return "protect"
	case "memfd_create":
		return "create"
	case "process_vm_readv":
		return "read"
	case "process_vm_writev":
		return "write"
	case "ptrace":
		return "ptrace"
	}
	return strings.ToLower(name)
}

func traceeArg(object map[string]any, names ...string) string {
	want := map[string]bool{}
	for _, name := range names {
		want[strings.ToLower(name)] = true
	}
	if args, ok := object["args"].([]any); ok {
		for _, raw := range args {
			arg, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(jsonString(arg["name"])))
			if !want[name] {
				continue
			}
			value := jsonString(arg["value"])
			if value == "" {
				value = fmt.Sprintf("%v", arg["value"])
			}
			return value
		}
	}
	for _, name := range names {
		if value := jsonString(object[name]); value != "" {
			return value
		}
	}
	return ""
}

func traceeArgInt(object map[string]any, names ...string) int64 {
	value := strings.TrimSpace(traceeArg(object, names...))
	if value == "" {
		return 0
	}
	if parsed, err := strconv.ParseInt(value, 0, 64); err == nil {
		return parsed
	}
	return 0
}

func traceeEndpoint(value string) (string, int64) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		parsed, _ := strconv.ParseInt(strings.TrimSpace(port), 10, 64)
		return host, parsed
	}
	if strings.Count(value, ":") > 1 {
		return strings.Trim(value, "[]"), 0
	}
	if host, port, ok := strings.Cut(value, ":"); ok {
		parsed, _ := strconv.ParseInt(strings.TrimSpace(port), 10, 64)
		return strings.Trim(host, "[]"), parsed
	}
	return value, 0
}

// traceeSocket reads the decoded SockAddr argument of a socket event. Tracee
// emits it as a nested object for security_socket_connect and as a string for
// the raw syscall events; local AF_UNIX connects are IPC, not C2 traffic.
func traceeSocket(object map[string]any) (family, addr string, port int64) {
	if args, ok := object["args"].([]any); ok {
		for _, raw := range args {
			arg, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(jsonString(arg["name"]))) {
			case "remote_addr", "sockaddr", "addr", "address":
			default:
				continue
			}
			switch value := arg["value"].(type) {
			case map[string]any:
				family = strings.ToUpper(firstString(value, "sa_family", "family"))
				addr = firstString(value, "sin_addr", "sin6_addr", "sun_path", "path", "addr")
				port = firstInt(value, "sin_port", "sin6_port", "port")
			case string:
				family = traceeSockFamily(value)
				addr, port = traceeEndpoint(value)
			}
			if family != "" {
				return family, addr, port
			}
		}
	}
	raw := traceeArg(object, "sockaddr", "addr", "address", "remote_addr")
	if raw == "" {
		return "", "", 0
	}
	family = traceeSockFamily(raw)
	addr, port = traceeEndpoint(raw)
	return family, addr, port
}

func traceeSockFamily(value string) string {
	upper := strings.ToUpper(value)
	for _, family := range []string{"AF_UNIX", "AF_INET6", "AF_INET"} {
		if strings.Contains(upper, family) {
			return family
		}
	}
	return ""
}

func traceeTime(object map[string]any) time.Time {
	raw, ok := object["timestamp"]
	if !ok {
		return telemetryTime(object)
	}
	switch typed := raw.(type) {
	case json.Number:
		if value, err := typed.Float64(); err == nil {
			return traceeUnixValue(value)
		}
	case float64:
		return traceeUnixValue(typed)
	case string:
		if parsed, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return parsed.UTC()
		}
	}
	return telemetryTime(object)
}

func traceeUnixValue(value float64) time.Time {
	switch {
	case value >= 1e18: // nanoseconds
		seconds := int64(value / 1e9)
		nanos := int64(value) % 1e9
		return time.Unix(seconds, nanos).UTC()
	case value >= 1e15: // microseconds
		seconds := int64(value / 1e6)
		micros := int64(value) % 1e6
		return time.Unix(seconds, micros*1e3).UTC()
	case value >= 1e12: // milliseconds
		seconds := int64(value / 1e3)
		millis := int64(value) % 1e3
		return time.Unix(seconds, millis*1e6).UTC()
	default:
		seconds := int64(value)
		nanos := int64((value - float64(seconds)) * float64(time.Second))
		return time.Unix(seconds, nanos).UTC()
	}
}
