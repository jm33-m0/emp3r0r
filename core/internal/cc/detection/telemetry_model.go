package detection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// processInfo is the best-known identity of one PID in a trace. It is built
// from PEB queries, process-start events, kernel callbacks, and Defender
// behavior events before event roles are assigned.
type processInfo struct {
	PID      int64
	Parent   int64
	Image    string
	Command  string
	Children map[int64]bool
}

// prepareTelemetry turns the parsed event stream into the attribution model the
// database and the loop consume: payload identity, process images, role, signal,
// and source coverage.
func prepareTelemetry(parsed *parsedTelemetry) {
	if parsed.Meta == nil {
		parsed.Meta = map[string]any{}
	}
	parsed.Events = dedupeTelemetryEvents(parsed.Events)
	parsed.PayloadPID, parsed.PayloadImage, parsed.Attribution = identifyPayload(parsed.Events, parsed.Source)
	processes, children := buildProcessMap(parsed.Events)
	for i := range parsed.Events {
		event := &parsed.Events[i]
		if event.Process == "" {
			event.Process = processes[event.PID].Image
		}
		if event.TargetImage == "" && event.TargetPID != 0 {
			event.TargetImage = processes[event.TargetPID].Image
		}
	}
	for i := range parsed.Events {
		classifyTelemetryEvent(&parsed.Events[i], parsed.PayloadPID, parsed.PayloadImage, children, processes)
	}
	parsed.Coverage = buildTelemetryCoverage(parsed.Events, parsed.Meta)
	parsed.First = time.Time{}
	parsed.Last = time.Time{}
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
}

func dedupeTelemetryEvents(events []telemetryEvent) []telemetryEvent {
	seen := make(map[string]int, len(events))
	out := make([]telemetryEvent, 0, len(events))
	for _, event := range events {
		if event.EventKey == "" {
			event.EventKey = telemetryObjectKey(event.Attrs, "")
		}
		if index, ok := seen[event.EventKey]; ok {
			if telemetryEventWeight(event) > telemetryEventWeight(out[index]) {
				out[index] = event
			}
			continue
		}
		seen[event.EventKey] = len(out)
		out = append(out, event)
	}
	return out
}

func telemetryEventWeight(event telemetryEvent) int {
	weight := 0
	for _, value := range []string{
		event.Event, event.Provider, event.Process, event.Path, event.Image,
		event.TargetImage, event.Protection, event.Status, event.Stack, event.Command,
	} {
		if value != "" {
			weight++
		}
	}
	if event.PID != 0 {
		weight++
	}
	if event.ActorPID != 0 {
		weight++
	}
	return weight
}

// identifyPayload finds the detonated process from its PEB query. There is no
// fallback to an arbitrary PID: a capture that never observed the payload PEB is
// reported as unknown instead of attributing MsMpEng events to the sample.
func identifyPayload(events []telemetryEvent, source string) (int64, string, string) {
	type candidate struct {
		pid   int64
		image string
		order int
		hits  int
	}
	var candidates []candidate
	seen := map[int64]int{}
	for index, event := range events {
		if !isPEBEvent(event) {
			continue
		}
		image := strings.TrimSpace(event.Image)
		if image == "" || isSystemImage(image) || looksLikeScanner(image) {
			continue
		}
		if position, ok := seen[event.PID]; ok {
			if candidates[position].image == "" {
				candidates[position].image = image
			}
			continue
		}
		seen[event.PID] = len(candidates)
		candidates = append(candidates, candidate{pid: event.PID, image: image, order: index})
	}
	for index := range candidates {
		for _, event := range events {
			if event.PID == candidates[index].pid || event.ActorPID == candidates[index].pid ||
				event.TargetPID == candidates[index].pid {
				candidates[index].hits++
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].hits == candidates[j].hits {
			return candidates[i].order < candidates[j].order
		}
		return candidates[i].hits > candidates[j].hits
	})
	if len(candidates) > 0 {
		return candidates[0].pid, candidates[0].image, "peb"
	}
	if strings.EqualFold(source, "defender_observer") {
		counts := map[int64]int{}
		images := map[int64]string{}
		order := map[int64]int{}
		for index, event := range events {
			if event.PID == 0 || looksLikeScanner(event.Process) {
				continue
			}
			counts[event.PID]++
			if _, ok := order[event.PID]; !ok {
				order[event.PID] = index
			}
			if images[event.PID] == "" && event.Process != "" {
				images[event.PID] = event.Process
			}
		}
		var best int64
		for pid := range counts {
			if best == 0 || counts[pid] > counts[best] ||
				(counts[pid] == counts[best] && order[pid] < order[best]) {
				best = pid
			}
		}
		if best != 0 {
			return best, images[best], "observer"
		}
	}
	return 0, "", "unknown"
}

func isPEBEvent(event telemetryEvent) bool {
	if !strings.EqualFold(event.Type, "process_query") && !strings.EqualFold(event.Type, "proces_query") {
		return false
	}
	return strings.EqualFold(event.Event, "peb") || strings.EqualFold(event.Operation, "peb")
}

// buildProcessMap resolves PID to image for event details and target images.
func buildProcessMap(events []telemetryEvent) (map[int64]processInfo, map[int64]bool) {
	processes := map[int64]processInfo{}
	children := map[int64]bool{}
	update := func(pid, parent int64, image, command string) {
		if pid == 0 {
			return
		}
		info := processes[pid]
		info.PID = pid
		if parent != 0 {
			info.Parent = parent
		}
		if image != "" {
			info.Image = image
		}
		if command != "" {
			info.Command = command
		}
		processes[pid] = info
	}
	for _, event := range events {
		switch {
		case isPEBEvent(event):
			update(event.PID, event.ParentPID, event.Image, event.Command)
		case event.Category == "process" && event.Operation == "create":
			update(event.PID, event.ActorPID, event.Image, event.Command)
			if event.ActorPID != 0 && event.PID != 0 {
				children[event.PID] = true
				parent := processes[event.ActorPID]
				if parent.Children == nil {
					parent.Children = map[int64]bool{}
				}
				parent.Children[event.PID] = true
				processes[event.ActorPID] = parent
			}
		case event.Type == "kernel" && event.Image != "":
			update(event.PID, event.ParentPID, event.Image, event.Command)
		case event.Category == "defender" && event.Operation == "create":
			update(event.PID, event.ParentPID, event.Image, event.Command)
		}
	}
	return processes, children
}

func classifyTelemetryEvent(event *telemetryEvent, payloadPID int64, payloadImage string, children map[int64]bool, processes map[int64]processInfo) {
	if event.ActorPID == 0 {
		event.ActorPID = event.PID
	}
	if event.Process == "" {
		event.Process = processes[event.PID].Image
	}
	if event.TargetImage == "" && event.TargetPID != 0 {
		event.TargetImage = processes[event.TargetPID].Image
	}
	if event.Signal == "" {
		event.Signal = "signal"
	}
	if event.Role == "" {
		event.Role = telemetryRole(event, payloadPID, payloadImage, children)
	}
	event.Signal = telemetrySignal(event, payloadPID, payloadImage)
	if (event.Role == "ambient" || event.Role == "unknown") && event.Signal != "verdict" {
		event.Signal = "noise"
	}
}

func telemetryRole(event *telemetryEvent, payloadPID int64, payloadImage string, children map[int64]bool) string {
	if event.Category == "analysis" {
		return "payload"
	}
	if payloadPID == 0 {
		return "unknown"
	}
	subject := event.PID
	actor := event.ActorPID
	image := event.Process
	if image == "" && subject == payloadPID {
		image = payloadImage
	}
	if event.Category == "defender" {
		switch {
		case subject == payloadPID, sameWindowsPath(image, payloadImage):
			return "payload-scan"
		case actor == payloadPID:
			return "payload"
		default:
			return "ambient"
		}
	}
	switch {
	case actor == payloadPID:
		return "payload"
	case subject == payloadPID:
		return "payload-target"
	case children[actor], children[subject]:
		return "payload-child"
	case event.TargetPID == payloadPID:
		return "payload-target"
	default:
		return "ambient"
	}
}

func telemetrySignal(event *telemetryEvent, payloadPID int64, payloadImage string) string {
	switch event.Category {
	case "defender":
		if event.Severity == "critical" || defenderThreatName(event.Event, map[string]any{"name": event.Event}) != "" {
			return "verdict"
		}
		return defenderEventSignal(event.Event)
	case "query":
		return "info"
	case "analysis":
		if event.Severity == "critical" || event.Severity == "high" || event.Severity == "medium" {
			return "signal"
		}
		return "info"
	case "image", "module":
		if event.Image == "" || isSystemImage(event.Image) || sameWindowsPath(event.Image, payloadImage) {
			return "baseline"
		}
		return "signal"
	case "process":
		if event.Operation == "create" {
			return "signal"
		}
		return "baseline"
	case "thread":
		return "baseline"
	case "memory":
		if event.Operation == "read" {
			return "info"
		}
		return "signal"
	case "audit":
		if event.Role == "payload" || event.Role == "payload-child" {
			return "signal"
		}
		return "scan"
	case "file":
		if event.Role != "payload" && event.Role != "payload-child" {
			return "noise"
		}
		if event.Path == "" || isSystemImage(event.Path) {
			return "baseline"
		}
		return "signal"
	case "network":
		if event.Role != "payload" && event.Role != "payload-child" {
			return "noise"
		}
		return "signal"
	case "hook":
		if event.Role != "payload" && event.Role != "payload-child" {
			return "noise"
		}
		return "signal"
	default:
		if payloadPID != 0 && event.Role == "payload" && event.Event != "" {
			return "signal"
		}
	}
	return "noise"
}

func defenderEventSignal(event string) string {
	lower := strings.ToLower(event)
	for _, noise := range []string{
		"bminternal", "bmetw", "cache ", "moac", "expensiveoperation",
		"processmonitorflags", "stream scan request", "bmnotificationhandlestart", "bmnotificationhandlestop",
	} {
		if strings.Contains(lower, noise) {
			return "noise"
		}
	}
	return "scan"
}

func buildTelemetryCoverage(events []telemetryEvent, meta map[string]any) TelemetryCoverage {
	coverage := TelemetryCoverage{
		Providers:  map[string]int{},
		Categories: map[string]int{},
		Roles:      map[string]int{},
		Signals:    map[string]int{},
		Analyzers:  map[string]string{},
	}
	delivered := map[string]bool{}
	for _, event := range events {
		if event.Provider != "" {
			if provider := sanitizeLine(event.Provider); provider != "" {
				coverage.Providers[provider]++
			}
			if strings.Contains(event.Provider, "Microsoft-Windows-Kernel") ||
				strings.Contains(event.Provider, "Microsoft-Antimalware-Engine") ||
				strings.Contains(event.Provider, "Microsoft-Windows-Threat-Intelligence") {
				delivered["etw"] = true
			}
		}
		if strings.EqualFold(event.Provider, "Microsoft-Windows-Threat-Intelligence") ||
			strings.HasPrefix(strings.ToUpper(event.Event), "KERNEL_THREATINT_") {
			delivered["etwti"] = true
		}
		if strings.EqualFold(event.Type, "kernel") {
			delivered["kernel"] = true
		}
		if strings.EqualFold(event.Type, "dll") {
			delivered["hook"] = true
		}
		if strings.Contains(event.Provider, "Antimalware") {
			delivered["antimalware"] = true
		}
		if looksLikeScanner(event.Process) || looksLikeScanner(event.TargetImage) {
			delivered["defender_trace"] = true
		}
		coverage.Categories[event.Category]++
		coverage.Roles[event.Role]++
		coverage.Signals[event.Signal]++
		if event.Category == "analysis" {
			recordAnalyzerCoverage(&coverage, event)
		}
	}
	expected := map[string]bool{}
	for name, key := range map[string]string{
		"etw": "do_etw", "etwti": "do_etwti", "kernel": "do_kernel", "hook": "do_hook",
		"antimalware": "do_antimalwareengine", "defender_trace": "do_defendertrace",
	} {
		if metaBool(meta, key) {
			expected[name] = true
		}
	}
	coverage.Delivered = sortedKeys(delivered)
	coverage.Expected = sortedKeys(expected)
	for name := range expected {
		if !delivered[name] {
			coverage.Missing = append(coverage.Missing, name)
		}
	}
	sort.Strings(coverage.Missing)
	return sanitizeTelemetryCoverage(coverage)
}

// recordAnalyzerCoverage turns analyzer status and errors into a visible
// coverage gap. A failed scan is not evidence that the artifact is clean.
func recordAnalyzerCoverage(coverage *TelemetryCoverage, event telemetryEvent) {
	name := strings.TrimSpace(event.Event)
	if name == "" {
		return
	}
	var attrs map[string]any
	_ = json.Unmarshal([]byte(event.Attrs), &attrs)
	status := "ok"
	if value, ok := attrs["errors"]; ok && value != nil {
		text := strings.TrimSpace(fmt.Sprintf("%v", value))
		if text != "" && text != "<nil>" {
			status = "failed: " + clip(text, 160)
		}
	}
	if value, ok := attrs["status"].(string); ok && strings.EqualFold(value, "failed") && status == "ok" {
		status = "failed"
	}
	if name == "dynamic/analysis_metadata" {
		if started, ok := attrs["analysis_started"].(bool); ok && !started {
			status = "not started"
		}
		if early, ok := attrs["early_termination"].(bool); ok && early {
			status = "early termination"
		}
	}
	coverage.Analyzers[name] = status
	if status != "ok" {
		coverage.Missing = append(coverage.Missing, name+": "+status)
	}
}

func metaBool(meta map[string]any, key string) bool {
	switch typed := meta[key].(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true") || typed == "1"
	case json.Number:
		return typed.String() != "0"
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	}
	return false
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// normalizeTelemetryObject converts one RedEdr or DefenderObserver JSON object
// into one or more normalized events. One loaded_dll query expands into one
// event per DLL so every module the payload loaded is queryable.
func normalizeTelemetryObject(source string, object map[string]any) []telemetryEvent {
	if strings.Contains(strings.ToLower(source), "defender") || isDefenderObserver(object) {
		return []telemetryEvent{normalizeDefenderObserverEvent(object)}
	}
	eventType := strings.ToLower(strings.TrimSpace(jsonString(object["type"])))
	switch eventType {
	case "meta":
		return nil
	case "process_query", "proces_query":
		return normalizeQueryEvents(object)
	case "kernel":
		return []telemetryEvent{normalizeKernelCallback(object)}
	case "dll":
		return []telemetryEvent{normalizeHookEvent(object)}
	}
	return []telemetryEvent{normalizeETWEvent(object)}
}

func normalizeQueryEvents(object map[string]any) []telemetryEvent {
	funcName := strings.ToLower(firstString(object, "func", "event"))
	base := telemetryEvent{
		Type:      "process_query",
		EventKey:  telemetryObjectKey(encodeObject(object), ""),
		PID:       firstInt(object, "pid"),
		TID:       firstInt(object, "tid"),
		ParentPID: firstInt(object, "parent_pid"),
		Category:  "query",
		Operation: funcName,
		Event:     funcName,
		Attrs:     encodeObject(object),
		TS:        telemetryTime(object),
	}
	if funcName == "loaded_dll" {
		dlls, _ := object["dlls"].([]any)
		if len(dlls) == 0 {
			base.Category = "module"
			base.Image = ""
			base.Signal = "noise"
			return []telemetryEvent{base}
		}
		out := make([]telemetryEvent, 0, len(dlls))
		for index, item := range dlls {
			dll, ok := item.(map[string]any)
			if !ok {
				continue
			}
			event := base
			event.EventKey = telemetryObjectKey(encodeObject(object), "dll:"+strconv.Itoa(index))
			event.Image = firstString(dll, "name", "path")
			event.Address = firstInt(dll, "addr", "base")
			event.Size = firstInt(dll, "size")
			event.Category = "module"
			out = append(out, event)
		}
		if len(out) == 0 {
			base.Category = "module"
			return []telemetryEvent{base}
		}
		return out
	}
	base.Image = firstString(object, "image_path")
	base.Command = firstString(object, "commandline")
	base.Attrs = encodeObject(object)
	return []telemetryEvent{base}
}

func normalizeKernelCallback(object map[string]any) telemetryEvent {
	funcName := strings.ToLower(strings.TrimSpace(jsonString(object["func"])))
	event := telemetryEvent{
		Type:      "kernel",
		EventKey:  telemetryObjectKey(encodeObject(object), ""),
		Event:     funcName,
		Operation: funcName,
		PID:       firstInt(object, "pid"),
		ActorPID:  firstInt(object, "krn_pid", "ppid"),
		ParentPID: firstInt(object, "ppid"),
		TID:       firstInt(object, "threadid"),
		Image:     firstString(object, "name", "image"),
		Category:  "other",
		Attrs:     encodeObject(object),
		TS:        telemetryTime(object),
	}
	switch {
	case strings.Contains(funcName, "process_create"):
		event.Category, event.Operation = "process", "create"
	case strings.Contains(funcName, "process_exit"), strings.Contains(funcName, "process_stop"):
		event.Category, event.Operation = "process", "exit"
	case strings.Contains(funcName, "thread_create"):
		event.Category, event.Operation = "thread", "start"
	case strings.Contains(funcName, "thread_exit"), strings.Contains(funcName, "thread_stop"):
		event.Category, event.Operation = "thread", "stop"
	case strings.Contains(funcName, "image_load"):
		event.Category, event.Operation = "image", "load"
	case strings.Contains(funcName, "image_unload"):
		event.Category, event.Operation = "image", "unload"
	}
	return event
}

func normalizeHookEvent(object map[string]any) telemetryEvent {
	funcName := strings.TrimSpace(jsonString(object["func"]))
	return telemetryEvent{
		Type:       "dll",
		EventKey:   telemetryObjectKey(encodeObject(object), ""),
		Event:      funcName,
		Operation:  funcName,
		PID:        firstInt(object, "pid"),
		TID:        firstInt(object, "tid"),
		Address:    firstInt(object, "addr", "addr_req"),
		Size:       firstInt(object, "size", "size_req"),
		Protection: jsonString(object["protect"]),
		Status:     jsonString(object["return"]),
		Category:   "hook",
		Attrs:      encodeObject(object),
		TS:         telemetryTime(object),
	}
}

func normalizeETWEvent(object map[string]any) telemetryEvent {
	eventName := strings.TrimSpace(jsonString(object["event"]))
	provider := jsonString(object["etw_provider_name"])
	eventType := strings.TrimSpace(jsonString(object["type"]))
	event := telemetryEvent{
		Type:       eventType,
		EventKey:   telemetryObjectKey(encodeObject(object), ""),
		Event:      eventName,
		Provider:   provider,
		EventID:    firstInt(object, "etw_event_id"),
		PID:        firstInt(object, "etw_pid", "processid", "pid"),
		TID:        firstInt(object, "etw_tid", "threadid"),
		ActorPID:   firstInt(object, "etw_pid", "pid"),
		Category:   redEdrCategoryV2(provider, eventName, eventType, object),
		Process:    firstString(object, "etw_process", "process_name"),
		Image:      firstString(object, "imagename", "imagepath"),
		Path:       firstString(object, "filename", "filepath"),
		Address:    firstInt(object, "imagebase", "image_base", "baseaddress", "addr"),
		Size:       firstInt(object, "imagesize", "regionsize", "size"),
		Protection: jsonString(object["protectionmask"]),
		Status:     firstString(object, "operationstatus", "returncode", "return", "exitcode"),
		Command:    firstString(object, "commandline"),
		Proto:      networkProto(eventName),
		SrcAddr:    attrString(object, "saddr"),
		SrcPort:    portValue(object, "sport"),
		DstAddr:    attrString(object, "daddr"),
		DstPort:    portValue(object, "dport"),
		Bytes:      firstInt(object, "bytescopied", "size"),
		Access:     firstInt(object, "desiredaccess", "accessmask"),
		TargetPID:  firstInt(object, "targetprocessid", "processid", "targetpid"),
		TargetTID:  firstInt(object, "targetthreadid", "targettid"),
		ParentPID:  firstInt(object, "parentprocessid", "parentpid"),
		Stack:      stackSummary(object),
		Attrs:      encodeObject(object),
	}
	switch event.Category {
	case "process":
		switch {
		case strings.HasPrefix(eventName, "ProcessStart"):
			event.Operation = "create"
			event.PID = firstInt(object, "processid", "pid")
			event.ActorPID = firstInt(object, "parentprocessid", "parentpid", "ppid")
			if event.ActorPID == 0 {
				event.ActorPID = firstInt(object, "etw_pid")
			}
			event.ParentPID = event.ActorPID
		case strings.HasPrefix(eventName, "ProcessStop"):
			event.Operation, event.PID = "exit", firstInt(object, "processid")
		default:
			event.Operation = "process"
		}
	case "image":
		if strings.HasPrefix(eventName, "ImageUnload") {
			event.Operation = "unload"
		} else {
			event.Operation = "load"
		}
		event.PID = firstInt(object, "processid", "etw_pid")
		event.ActorPID = event.PID
	case "thread":
		if strings.HasPrefix(eventName, "ThreadStop") {
			event.Operation = "stop"
		} else {
			event.Operation = "start"
		}
		event.PID = firstInt(object, "processid", "etw_pid")
		event.TID = firstInt(object, "threadid", "etw_tid")
		event.Address = firstInt(object, "startaddr", "win32startaddr")
	case "file":
		event.Operation = fileOperation(eventName)
		event.PID = firstInt(object, "etw_pid")
		event.ActorPID = event.PID
	case "network":
		event.Operation = "connect"
		if strings.Contains(strings.ToLower(eventName), "udp") {
			event.Operation = "datagram"
		}
		event.PID = firstInt(object, "etw_pid", "pid")
		event.ActorPID = event.PID
	case "audit":
		event.Operation = auditOperation(event.EventID)
		event.PID = firstInt(object, "etw_pid")
		event.ActorPID = event.PID
		event.Event = auditAPIName(event.EventID, eventName)
		event.TargetPID = firstInt(object, "targetprocessid")
		event.TargetTID = firstInt(object, "targetthreadid")
	case "memory":
		event.Operation = etwtiOperation(eventName)
		event.PID = firstInt(object, "callingprocessid", "etw_pid")
		event.ActorPID = event.PID
		event.TargetPID = firstInt(object, "targetprocessid")
		event.TargetTID = firstInt(object, "targetthreadid")
		event.Process = strings.Trim(firstString(object, "process_name"), `"`)
		event.Protection = firstString(object, "protectionmask", "vadavallocationprotect")
		event.Status = firstString(object, "operationstatus")
		if strings.EqualFold(eventName, "KERNEL_THREATINT_TASK_WRITEVM") {
			event.Bytes = firstInt(object, "bytescopied")
		}
	case "defender":
		event.Operation = "scan"
		event.PID = firstInt(object, "pid", "etw_pid")
		event.ActorPID = firstInt(object, "etw_pid", "pid")
		event.TargetPID = firstInt(object, "targetpid")
		event.Path = firstString(object, "filename", "path", "name", "imagepath", "basepath")
		event.Image = firstString(object, "imagepath", "basepath")
		event.Process = firstString(object, "etw_process", "process_name")
		event.ParentPID = firstInt(object, "parentpid")
		event.Command = firstString(object, "commandline")
		if strings.Contains(strings.ToLower(eventName), "processcreate") {
			event.Operation = "create"
		}
		if name := defenderThreatName(eventName, object); name != "" {
			event.Severity = "critical"
			event.Event = name
		}
	}
	if event.Path == "" && event.Category != "defender" {
		event.Path = firstString(object, "name")
	}
	if event.TS = telemetryTime(object); event.TS.IsZero() {
		event.TS = telemetryTimeKey(object, "createtime")
	}
	return event
}

func normalizeDefenderObserverEvent(object map[string]any) telemetryEvent {
	payload, _ := object["payload"].(map[string]any)
	event := telemetryEvent{
		Type:      "defender_observer",
		EventKey:  telemetryObjectKey(encodeObject(object), ""),
		Event:     firstString(object, "symbol", "summary", "task", "opcode"),
		Provider:  firstString(object, "providerName"),
		PID:       firstInt(object, "processId"),
		TID:       firstInt(object, "threadId"),
		Process:   firstString(object, "processName"),
		Category:  "defender",
		Operation: "scan",
		Attrs:     encodeObject(object),
	}
	if strings.Contains(strings.ToLower(event.Provider), "antimalware") ||
		strings.Contains(strings.ToLower(event.Provider), "defender") {
		event.Category = "defender"
	}
	if timestamp := jsonString(object["timestamp"]); timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
			event.TS = parsed.UTC()
		}
	}
	for key, value := range payload {
		text, ok := value.(string)
		if !ok || text == "" {
			continue
		}
		lower := strings.ToLower(key)
		switch {
		case strings.Contains(lower, "image"):
			if event.Image == "" {
				event.Image = text
			}
		case strings.Contains(lower, "path") || strings.Contains(lower, "file"):
			if event.Path == "" {
				event.Path = text
			}
		}
	}
	if name := defenderThreatName(event.Event, payload); name != "" {
		event.Severity = "critical"
		event.Event = name
	}
	return event
}

func redEdrCategoryV2(provider, event, eventType string, object map[string]any) string {
	if strings.EqualFold(eventType, "process_query") || strings.EqualFold(eventType, "proces_query") {
		return "query"
	}
	switch {
	case strings.Contains(provider, "Audit-API"):
		return "audit"
	case strings.Contains(provider, "Antimalware"):
		return "defender"
	case strings.Contains(provider, "Kernel-File"):
		return "file"
	case strings.Contains(provider, "Kernel-Network"):
		return "network"
	case strings.Contains(provider, "Threat-Intelligence"):
		return "memory"
	case strings.Contains(provider, "Kernel-Process"):
		switch {
		case strings.HasPrefix(event, "ImageLoad"), strings.HasPrefix(event, "ImageUnload"):
			return "image"
		case strings.HasPrefix(event, "ProcessStart"):
			return "process"
		case strings.HasPrefix(event, "ThreadStart"):
			return "thread"
		}
	case looksLikeScanner(firstString(object, "etw_process", "process_name")):
		return "defender"
	}
	return "other"
}

func fileOperation(event string) string {
	lower := strings.ToLower(event)
	switch {
	case strings.Contains(lower, "create"), strings.Contains(lower, "newfile"):
		return "create"
	case strings.Contains(lower, "write"):
		return "write"
	case strings.Contains(lower, "delete"):
		return "delete"
	case strings.Contains(lower, "rename"):
		return "rename"
	case strings.Contains(lower, "read"):
		return "read"
	}
	return "file"
}

func etwtiOperation(event string) string {
	action := strings.TrimPrefix(strings.ToUpper(event), "KERNEL_THREATINT_TASK_")
	switch {
	case strings.Contains(action, "WRITEVM"):
		return "write"
	case strings.Contains(action, "READVM"):
		return "read"
	case strings.Contains(action, "PROTECTVM"):
		return "protect"
	case strings.Contains(action, "ALLOCVM"):
		return "allocate"
	case strings.Contains(action, "SUSPENDRESUME"):
		return "suspend"
	case strings.Contains(action, "MAPVIEW"):
		return "map"
	}
	return strings.ToLower(action)
}

func auditOperation(eventID int64) string {
	switch eventID {
	case 3:
		return "symlink"
	case 4:
		return "setcontext"
	case 5:
		return "openprocess"
	case 6:
		return "openthread"
	}
	return fmt.Sprintf("audit-%d", eventID)
}

func auditAPIName(eventID int64, fallback string) string {
	switch eventID {
	case 3:
		return "CreateSymbolicLink"
	case 4:
		return "SetContextThread"
	case 5:
		return "OpenProcess"
	case 6:
		return "OpenThread"
	}
	if fallback == "" {
		return "AuditAPI"
	}
	return fallback
}

func networkProto(event string) string {
	lower := strings.ToLower(event)
	switch {
	case strings.Contains(lower, "tcp"):
		return "tcp"
	case strings.Contains(lower, "udp"):
		return "udp"
	}
	return ""
}

func attrString(object map[string]any, key string) string {
	value, ok := object[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		if strings.EqualFold(typed, "unsupported") {
			return ""
		}
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(typed, 10)
	}
	return ""
}

func portValue(object map[string]any, key string) int64 {
	value := attrString(object, key)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func stackSummary(object map[string]any) string {
	frames, _ := object["stack_trace"].([]any)
	var parts []string
	for _, frame := range frames {
		if len(parts) >= 6 {
			break
		}
		switch typed := frame.(type) {
		case map[string]any:
			info := firstString(typed, "addr_info", "module", "name")
			if info != "" {
				parts = append(parts, info)
			}
		case string:
			if typed != "" {
				parts = append(parts, typed)
			}
		}
	}
	return clip(strings.Join(parts, " <- "), 500)
}

func telemetryObjectKey(attrs, suffix string) string {
	key := ""
	if attrs != "" {
		var object map[string]any
		dec := json.NewDecoder(strings.NewReader(attrs))
		dec.UseNumber()
		if dec.Decode(&object) == nil {
			traceID := intFrom(object, "trace_id")
			id := intFrom(object, "id")
			typ := jsonString(object["type"])
			event := firstString(object, "event", "func")
			// A trace-local id is unique with its trace id. DefenderObserver
			// and single-object imports have no trace id, so their timestamp
			// and content must distinguish repeated ids.
			if id != 0 && traceID != 0 {
				key = fmt.Sprintf("%d:%d:%s:%s", traceID, id, typ, event)
			}
		}
	}
	if key == "" {
		sum := sha256.Sum256([]byte(attrs))
		key = "sha256:" + hex.EncodeToString(sum[:12])
	}
	if suffix != "" {
		key += ":" + suffix
	}
	return key
}

func isSystemImage(path string) bool {
	normalized := normalizeWindowsPath(path)
	if normalized == "" {
		return true
	}
	// Module-load events carry the bare image name (KERNEL32.DLL), not a path.
	// A name without a directory component is resolved by the loader search
	// order, which only searches system directories, so it is a system image.
	if !strings.Contains(normalized, `\`) {
		return true
	}
	return strings.Contains(normalized, `\windows\`) ||
		strings.Contains(normalized, `\program files\`) ||
		strings.Contains(normalized, `\programdata\microsoft\windows defender\`) ||
		strings.Contains(normalized, `\systemroot\`)
}

func looksLikeScanner(name string) bool {
	lower := strings.ToLower(strings.ReplaceAll(name, "/", `\`))
	return strings.Contains(lower, "msmpeng") || strings.Contains(lower, "mpengine") ||
		strings.Contains(lower, "mssense") || strings.Contains(lower, "windefend")
}

// deriveTelemetryFromStored re-normalizes one stored attrs blob. It is used by
// the v1-to-v2 migration so existing traces gain attribution and the new
// event fields without a re-detonation.
func deriveTelemetryFromStored(source, attrs string) []telemetryEvent {
	if strings.TrimSpace(attrs) == "" {
		return nil
	}
	var object map[string]any
	dec := json.NewDecoder(strings.NewReader(attrs))
	dec.UseNumber()
	if dec.Decode(&object) != nil {
		return nil
	}
	normalized := normalizeTelemetryObject(source, object)
	for i := range normalized {
		normalized[i].Source = source
	}
	return normalized
}

// Stats returns the bounded telemetry summary for one trace.
func (t *TelemetryDB) Stats(ctx context.Context, traceID int64) (TelemetryStats, error) {
	stats := TelemetryStats{
		TraceID:    traceID,
		ByCategory: map[string]int{}, ByRule: map[string]int{}, BySeverity: map[string]int{},
	}
	if err := t.db.QueryRowContext(ctx,
		`SELECT event_count, COALESCE(findings_count, 0) FROM traces WHERE id = ?`, traceID).
		Scan(&stats.Events, &stats.Findings); err != nil {
		return TelemetryStats{}, fmt.Errorf("load trace stats: %w", err)
	}
	counts, err := t.rows(ctx, `SELECT payload_role, signal, category, count(*) AS n
		FROM events WHERE trace_pk = ? GROUP BY payload_role, signal, category`, traceID)
	if err != nil {
		return TelemetryStats{}, err
	}
	for _, row := range counts {
		count := row.int("n")
		if category := sanitizeLine(row.string("category")); category != "" {
			stats.ByCategory[category] += int(count)
		}
		switch row.string("payload_role") {
		case "payload", "payload-child":
			stats.PayloadEvents += int(count)
		}
		if row.string("signal") == "signal" {
			stats.SignalEvents += int(count)
		}
	}
	findings, err := t.rows(ctx, `SELECT severity, rule, count(*) AS n
		FROM findings WHERE trace_pk = ? GROUP BY severity, rule`, traceID)
	if err != nil {
		return TelemetryStats{}, err
	}
	for _, row := range findings {
		if severity := sanitizeLine(row.string("severity")); severity != "" {
			stats.BySeverity[severity] += int(row.int("n"))
		}
		if rule := sanitizeLine(row.string("rule")); rule != "" {
			stats.ByRule[rule] += int(row.int("n"))
		}
	}
	var coverageRaw string
	if err := t.db.QueryRowContext(ctx, `SELECT coverage FROM traces WHERE id = ?`, traceID).
		Scan(&coverageRaw); err == nil && coverageRaw != "" {
		_ = json.Unmarshal([]byte(coverageRaw), &stats.Coverage)
		stats.Coverage = sanitizeTelemetryCoverage(stats.Coverage)
	}
	return stats, nil
}

// migrateTelemetrySchema backfills v2 attribution fields. The old schema stored
// just enough raw attrs to rebuild every event, so existing traces stay usable
// without detonating the payload again.
func migrateTelemetrySchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read telemetry schema version: %w", err)
	}
	if version >= TelemetrySchemaVersion {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin telemetry migration: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, source, meta FROM traces ORDER BY id`)
	if err != nil {
		return fmt.Errorf("read traces for migration: %w", err)
	}
	type traceRow struct {
		id, source, meta string
	}
	var traces []traceRow
	for rows.Next() {
		var id int64
		var source, meta string
		if err := rows.Scan(&id, &source, &meta); err != nil {
			rows.Close()
			return fmt.Errorf("scan trace for migration: %w", err)
		}
		traces = append(traces, traceRow{id: strconv.FormatInt(id, 10), source: source, meta: meta})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, trace := range traces {
		if err := migrateTraceEvents(tx, trace.id, trace.source, trace.meta); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, TelemetrySchemaVersion)); err != nil {
		return fmt.Errorf("write telemetry schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry migration: %w", err)
	}
	return nil
}

func migrateTraceEvents(tx *sql.Tx, traceID, source, metaRaw string) error {
	var payloadID int64
	if err := tx.QueryRow(`SELECT COALESCE(payload_id, 0) FROM traces WHERE id = ?`, traceID).Scan(&payloadID); err != nil {
		return fmt.Errorf("load trace %s: %w", traceID, err)
	}
	rows, err := tx.Query(`SELECT id, attrs FROM events WHERE trace_pk = ? ORDER BY id`, traceID)
	if err != nil {
		return fmt.Errorf("load trace %s events: %w", traceID, err)
	}
	type storedEvent struct {
		id      int64
		attrs   string
		derived []telemetryEvent
	}
	var stored []storedEvent
	var events []telemetryEvent
	for rows.Next() {
		var row storedEvent
		if err := rows.Scan(&row.id, &row.attrs); err != nil {
			rows.Close()
			return fmt.Errorf("scan trace %s event: %w", traceID, err)
		}
		row.derived = deriveTelemetryFromStored(source, row.attrs)
		stored = append(stored, row)
		events = append(events, row.derived...)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	parsed := parsedTelemetry{Source: source, Events: events, Meta: map[string]any{}}
	if metaRaw != "" {
		dec := json.NewDecoder(strings.NewReader(metaRaw))
		dec.UseNumber()
		_ = dec.Decode(&parsed.Meta)
	}
	prepareTelemetry(&parsed)
	// prepareTelemetry copies events while deduplicating and classifying them;
	// map the classified result back onto each stored row before writing.
	classified := make(map[string]telemetryEvent, len(parsed.Events))
	for _, event := range parsed.Events {
		classified[event.EventKey] = event
	}
	for index := range stored {
		for pos := range stored[index].derived {
			if event, ok := classified[stored[index].derived[pos].EventKey]; ok {
				stored[index].derived[pos] = event
			}
		}
	}
	coverage, _ := json.Marshal(parsed.Coverage)
	parsed.Meta["payload_pid"] = parsed.PayloadPID
	parsed.Meta["payload_image"] = parsed.PayloadImage
	parsed.Meta["attribution"] = parsed.Attribution
	parsed.Meta["coverage"] = parsed.Coverage
	meta, _ := json.Marshal(parsed.Meta)
	if _, err := tx.Exec(`UPDATE traces SET payload_pid = ?, payload_image = ?, attribution = ?,
		coverage = ?, event_count = ?, findings_count = 0, findings_computed = 0, meta = ? WHERE id = ?`,
		nullableInt(parsed.PayloadPID), parsed.PayloadImage, parsed.Attribution, string(coverage),
		len(parsed.Events), string(meta), traceID); err != nil {
		return fmt.Errorf("update trace %s: %w", traceID, err)
	}
	if _, err := tx.Exec(`DELETE FROM findings WHERE trace_pk = ?`, traceID); err != nil {
		return fmt.Errorf("clear trace %s findings: %w", traceID, err)
	}
	update, err := tx.Prepare(`UPDATE events SET source = ?, event_key = ?, ts_ns = ?, type = ?,
		event = ?, provider = ?, event_id = ?, pid = ?, tid = ?, actor_pid = ?, target_pid = ?,
		target_tid = ?, parent_pid = ?, operation = ?, process = ?, target_image = ?, path = ?,
		image = ?, address = ?, size = ?, protection = ?, access = ?, status = ?, command = ?,
		proto = ?, src_addr = ?, src_port = ?, dst_addr = ?, dst_port = ?, bytes = ?, stack = ?,
		category = ?, severity = ?, signal = ?, payload_role = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer update.Close()
	insert, err := tx.Prepare(`INSERT INTO events(payload_id, trace_pk, source, event_key, ts_ns,
		type, event, provider, event_id, pid, tid, actor_pid, target_pid, target_tid, parent_pid,
		operation, process, target_image, path, image, address, size, protection, access, status,
		command, proto, src_addr, src_port, dst_addr, dst_port, bytes, stack, category, severity,
		signal, payload_role, attrs) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insert.Close()
	for _, row := range stored {
		if len(row.derived) == 0 {
			if _, err := tx.Exec(`UPDATE events SET signal = 'noise', payload_role = 'unknown' WHERE id = ?`, row.id); err != nil {
				return err
			}
			continue
		}
		first := row.derived[0]
		if _, err := update.Exec(source, first.EventKey, nullableTS(first.TS), first.Type, first.Event,
			first.Provider, nullableInt(first.EventID), nullableInt(first.PID), nullableInt(first.TID),
			nullableInt(first.ActorPID), nullableInt(first.TargetPID), nullableInt(first.TargetTID),
			nullableInt(first.ParentPID), first.Operation, first.Process, first.TargetImage,
			first.Path, first.Image, nullableInt(first.Address), nullableInt(first.Size),
			first.Protection, nullableInt(first.Access), first.Status, first.Command, first.Proto,
			first.SrcAddr, nullableInt(first.SrcPort), first.DstAddr, nullableInt(first.DstPort),
			nullableInt(first.Bytes), first.Stack, first.Category, first.Severity, first.Signal,
			first.Role, row.id); err != nil {
			return fmt.Errorf("update event %d: %w", row.id, err)
		}
		for _, extra := range row.derived[1:] {
			if _, err := insert.Exec(payloadID, traceID, source, extra.EventKey, nullableTS(extra.TS),
				extra.Type, extra.Event, extra.Provider, nullableInt(extra.EventID), nullableInt(extra.PID),
				nullableInt(extra.TID), nullableInt(extra.ActorPID), nullableInt(extra.TargetPID),
				nullableInt(extra.TargetTID), nullableInt(extra.ParentPID), extra.Operation,
				extra.Process, extra.TargetImage, extra.Path, extra.Image, nullableInt(extra.Address),
				nullableInt(extra.Size), extra.Protection, nullableInt(extra.Access), extra.Status,
				extra.Command, extra.Proto, extra.SrcAddr, nullableInt(extra.SrcPort), extra.DstAddr,
				nullableInt(extra.DstPort), nullableInt(extra.Bytes), extra.Stack, extra.Category,
				extra.Severity, extra.Signal, extra.Role, extra.Attrs); err != nil {
				return fmt.Errorf("insert migrated event: %w", err)
			}
		}
	}
	return nil
}

func nullableTS(ts time.Time) any {
	if ts.IsZero() {
		return nil
	}
	return ts.UnixNano()
}
