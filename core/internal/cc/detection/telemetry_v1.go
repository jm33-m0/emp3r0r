package detection

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LabTelemetrySchema is the sensor-neutral telemetry envelope. A lab box may
// implement the LitterBox HTTP contract with any sensor set, but every sensor
// reports this schema so the Windows and Linux paths share one parser.
const LabTelemetrySchema = "emp3r0r.telemetry/v1"

type labEnvelope struct {
	Schema   string             `json:"schema"`
	Lab      string             `json:"lab,omitempty"`
	Platform string             `json:"platform,omitempty"`
	Run      labRun             `json:"run"`
	Coverage TelemetryCoverage  `json:"coverage,omitempty"`
	Events   []labEnvelopeEvent `json:"events"`
}

type labRun struct {
	ID           string    `json:"id,omitempty"`
	Artifact     string    `json:"artifact,omitempty"`
	MD5          string    `json:"md5,omitempty"`
	SHA256       string    `json:"sha256,omitempty"`
	Platform     string    `json:"platform,omitempty"`
	ContainerID  string    `json:"container_id,omitempty"`
	PayloadPID   int64     `json:"payload_pid,omitempty"`
	PayloadImage string    `json:"payload_image,omitempty"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	FinishedAt   time.Time `json:"finished_at,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type labEnvelopeEvent struct {
	Timestamp   string         `json:"timestamp,omitempty"`
	TS          string         `json:"ts,omitempty"`
	Sensor      string         `json:"sensor,omitempty"`
	Provider    string         `json:"provider,omitempty"`
	Event       string         `json:"event,omitempty"`
	Category    string         `json:"category"`
	Operation   string         `json:"operation"`
	PID         int64          `json:"pid,omitempty"`
	TID         int64          `json:"tid,omitempty"`
	PPID        int64          `json:"ppid,omitempty"`
	ActorPID    int64          `json:"actor_pid,omitempty"`
	TargetPID   int64          `json:"target_pid,omitempty"`
	Process     string         `json:"process,omitempty"`
	Image       string         `json:"image,omitempty"`
	TargetImage string         `json:"target_image,omitempty"`
	Path        string         `json:"path,omitempty"`
	Command     string         `json:"command,omitempty"`
	Proto       string         `json:"proto,omitempty"`
	SrcAddr     string         `json:"src_addr,omitempty"`
	SrcPort     int64          `json:"src_port,omitempty"`
	DstAddr     string         `json:"dst_addr,omitempty"`
	DstPort     int64          `json:"dst_port,omitempty"`
	Bytes       int64          `json:"bytes,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Signal      string         `json:"signal,omitempty"`
	Attrs       map[string]any `json:"attrs,omitempty"`
}

// parseLabTelemetryV1 accepts the standardized sensor envelope before any
// legacy LitterBox/PenguinBox adapter runs. The envelope is intentionally
// platform-neutral: sensors normalize their native events in the box.
func parseLabTelemetryV1(data []byte) (parsedTelemetry, bool, error) {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil || !strings.EqualFold(strings.TrimSpace(header.Schema), LabTelemetrySchema) {
		return parsedTelemetry{}, false, nil
	}
	var envelope labEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return parsedTelemetry{}, true, fmt.Errorf("decode lab telemetry: %w", err)
	}
	platform := strings.ToLower(strings.TrimSpace(firstNonEmpty(envelope.Platform, envelope.Run.Platform)))
	if platform != platformWindows && platform != platformLinux {
		return parsedTelemetry{}, true, fmt.Errorf("lab telemetry platform must be windows or linux")
	}
	if len(envelope.Events) > maxTelemetryEvents {
		return parsedTelemetry{}, true, fmt.Errorf("lab telemetry exceeds %d events", maxTelemetryEvents)
	}
	parsed := parsedTelemetry{
		Source:       "lab",
		Platform:     platform,
		ExternalID:   strings.TrimSpace(envelope.Run.ID),
		PayloadPID:   envelope.Run.PayloadPID,
		PayloadImage: strings.TrimSpace(envelope.Run.PayloadImage),
		Coverage:     envelope.Coverage,
		Meta: map[string]any{
			"schema":   LabTelemetrySchema,
			"platform": platform,
		},
	}
	if name := strings.TrimSpace(envelope.Lab); name != "" {
		parsed.Source = name
		parsed.Meta["lab"] = name
	}
	if envelope.Run.Artifact != "" || envelope.Run.MD5 != "" || envelope.Run.SHA256 != "" ||
		envelope.Run.ContainerID != "" || !envelope.Run.StartedAt.IsZero() ||
		!envelope.Run.FinishedAt.IsZero() || len(envelope.Run.Warnings) > 0 || envelope.Run.Error != "" {
		parsed.Meta["run"] = envelope.Run
	}
	if parsed.ExternalID == "" {
		parsed.ExternalID = strings.TrimSpace(envelope.Run.SHA256)
		if parsed.ExternalID != "" {
			parsed.ExternalID = "sha256:" + parsed.ExternalID
		}
	}
	for index, raw := range envelope.Events {
		category := strings.ToLower(strings.TrimSpace(raw.Category))
		operation := strings.ToLower(strings.TrimSpace(raw.Operation))
		if category == "" || operation == "" {
			return parsedTelemetry{}, true, fmt.Errorf("lab event %d requires category and operation", index)
		}
		event := telemetryEvent{
			Type:        "lab",
			Source:      parsed.Source,
			Event:       strings.TrimSpace(raw.Event),
			Provider:    strings.TrimSpace(firstNonEmpty(raw.Provider, raw.Sensor)),
			PID:         raw.PID,
			TID:         raw.TID,
			ParentPID:   raw.PPID,
			ActorPID:    raw.ActorPID,
			TargetPID:   raw.TargetPID,
			Process:     strings.TrimSpace(raw.Process),
			Image:       strings.TrimSpace(raw.Image),
			TargetImage: strings.TrimSpace(raw.TargetImage),
			Path:        strings.TrimSpace(raw.Path),
			Command:     strings.TrimSpace(raw.Command),
			Proto:       strings.TrimSpace(raw.Proto),
			SrcAddr:     strings.TrimSpace(raw.SrcAddr),
			SrcPort:     raw.SrcPort,
			DstAddr:     strings.TrimSpace(raw.DstAddr),
			DstPort:     raw.DstPort,
			Bytes:       raw.Bytes,
			Category:    category,
			Operation:   operation,
			Severity:    normalizeSeverity(raw.Severity),
			Signal:      strings.ToLower(strings.TrimSpace(raw.Signal)),
			Attrs:       encodeObject(raw.Attrs),
		}
		if event.Event == "" {
			event.Event = firstNonEmpty(event.Provider, category+"/"+operation)
		}
		if event.PID != 0 && event.ActorPID == 0 {
			event.ActorPID = event.PID
		}
		event.TS = parseLabTimestamp(firstNonEmpty(raw.Timestamp, raw.TS))
		event.EventKey = telemetryObjectKey(event.Attrs, "")
		if event.EventKey == "" {
			event.EventKey = fmt.Sprintf("%s|%s|%d|%d|%s", category, operation, event.PID, event.TS.UnixNano(), event.Path)
		}
		parsed.Events = append(parsed.Events, event)
	}
	if len(parsed.Events) == 0 {
		return parsedTelemetry{}, true, fmt.Errorf("lab telemetry has no events")
	}
	for _, event := range parsed.Events {
		if event.TS.IsZero() {
			continue
		}
		if parsed.First.IsZero() || event.TS.Before(parsed.First) {
			parsed.First = event.TS
		}
		if parsed.Last.IsZero() || event.TS.After(parsed.Last) {
			parsed.Last = event.TS
		}
	}
	return parsed, true, nil
}

func parseLabTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC()
	}
	if parsed, err := time.Parse("2006-01-02T15:04:05Z07:00", value); err == nil {
		return parsed.UTC()
	}
	return time.Time{}
}
