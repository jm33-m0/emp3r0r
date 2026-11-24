# Detection lab protocol

A detection lab is a sandbox that implements the LitterBox HTTP contract and runs one or more sensors inside the box. The lab is either Windows or Linux, but the telemetry it returns uses one sensor-neutral envelope so the detection pipeline does not need a platform-specific parser.

## Lab API

The endpoint must expose the LitterBox routes:

- `GET /health`
- `POST /upload`
- `POST /analyze/static/<id>`
- `POST /analyze/dynamic/<id>`
- `GET /api/results/{info,static,dynamic,risk}/<id>`
- `GET /api/edr/profiles`
- `GET /api/rules`

The default endpoints are `http://127.0.0.1:1337` for Windows and `http://127.0.0.1:1338` for Linux. Both live in `<workspace>/detection/labs.json`; `EMP3R0R_DETECTION_SANDBOX` remains a legacy override for both, and the CLI `--sandbox` flag selects one explicitly. A payload module opts into the loop with `"detection": true` in its manifest and declares its runtime platform with `"platform": "Linux"` or `"platform": "Windows"`.

## Sensor-neutral telemetry

A box may run Tracee, Falco, RedEdr, ETW, Defender, or another sensor. Sensors normalize their native events in the box and return one envelope from the dynamic result:

```json
{
  "schema": "emp3r0r.telemetry/v1",
  "lab": "windows-lab-a",
  "platform": "windows",
  "run": {
    "id": "run-20261122T120000Z-abc123",
    "artifact": "/var/lib/lab/uploads/abc123/payload",
    "md5": "abc123",
    "sha256": "…",
    "payload_pid": 4120,
    "payload_image": "C:\\Users\\Public\\payload.exe",
    "container_id": "process-4120",
    "started_at": "2026-11-22T12:00:00Z",
    "finished_at": "2026-11-22T12:00:30Z",
    "warnings": [],
    "error": ""
  },
  "coverage": {
    "delivered": ["defender", "etw"],
    "expected": ["defender", "etw"],
    "analyzers": {"defender": "ok", "etw": "ok"}
  },
  "events": [
    {
      "timestamp": "2026-11-22T12:00:01.250Z",
      "sensor": "defender",
      "provider": "Microsoft-Windows-Defender",
      "event": "Behavior:Win32/Example",
      "category": "defender",
      "operation": "verdict",
      "pid": 4120,
      "ppid": 4000,
      "process": "payload.exe",
      "image": "C:\\Users\\Public\\payload.exe",
      "path": "C:\\Users\\Public\\payload.exe",
      "severity": "critical",
      "signal": "verdict",
      "attrs": {"etw_event_id": 1116}
    }
  ]
}
```

### Required fields

- `schema` must be `emp3r0r.telemetry/v1`.
- `platform` or `run.platform` must be `windows` or `linux`.
- Each event must have `category` and `operation`.
- `timestamp` is RFC3339 or RFC3339Nano. A missing timestamp is allowed but creates less precise ordering.
- `attrs` is for sensor-specific detail and remains available to SQL and the model.

### Common event fields

| Field | Meaning |
| --- | --- |
| `sensor` / `provider` | Sensor identity; `sensor` is used when `provider` is absent |
| `event` | Sensor event or rule name |
| `category` | Normalized category such as `process`, `file`, `network`, `memory`, `kernel`, `namespace`, `defender`, `analysis`, or `ipc` |
| `operation` | Normalized operation such as `create`, `open`, `connect`, `protect`, `ptrace`, `verdict` |
| `pid`, `tid`, `ppid`, `actor_pid`, `target_pid` | Process identity |
| `process`, `image`, `path`, `command` | Process and object context |
| `proto`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `bytes` | Network context |
| `severity`, `signal` | Sensor severity and whether the event is a verdict, signal, baseline, or noise |

Sensors should put native fields the common model cannot represent in `attrs`. The detection pipeline keeps them and exposes them through `detection_query` using `json_extract`.


## Sensor requirements

- `/health` is authoritative for which static, dynamic, and EDR sensors exist. Do not build a plan from a hardcoded sensor list.
- `/api/rules` returns the static and behavioral rule inventory as file names. The rule names carried in events are the stable vocabulary; tuning must not rename a rule to change its behavior.
- Each event must carry a normalized `category` and `operation`. For syscall and LSM sensors, derive them from the native event type (`evt.type`, syscall name, or hook name), not from the rule name. A rule called “Anonymous Executable Memory” is still a memory/protect event because its native event is `mprotect`.
- `signal` separates actionable detections from context. A box should use `verdict` for a named high-confidence detection, `signal` for a named rule or behavioral detection, `baseline` for expected startup traffic, and `noise` for control-plane or runtime activity. `baseline` and `noise` are never counted as findings.
- Control-plane events must stay attributed to the runtime. A container runtime creating or entering namespaces is not a payload namespace change unless the event is attributed to the payload process.
- A missing or failed sensor is a coverage gap, not a clean result. It must appear in `coverage.missing` or `coverage.analyzers` with a failing status.
- A rule engine that is disabled or absent is also a coverage gap. `coverage.expected` must list the sensors the plan relies on, and `coverage.delivered` must list the sensors that produced at least one event.

### Severity normalization

Sensors normalize native priorities to `critical`, `high`, `medium`, `low`, or `info` before the event reaches the pipeline. The Falco mapping is:

| Falco priority | Normalized severity |
| --- | --- |
| `emergency`, `alert`, `critical` | `critical` |
| `error`, `warning` | `high` |
| `notice` | `medium` |
| `informational`, `info`, `debug` | `info` |

### Named rules and behavioral findings

A named rule engine such as Falco is the stable detection vocabulary. Its events use the rule name as `event` and carry the native event type in `attrs` (`evt.type`) for classification. A raw syscall sensor such as Tracee is the behavioral layer; generic findings derived from it must not be duplicated from named rule alerts. A box that returns both forms should keep them distinct in `provider` so the consumer can separate them without matching rule names.

Static analyzers follow the same model. A YARA match is one finding per matching rule, the rule name is the indicator, and `meta.severity` supplies the severity. `attrs` carries the matched strings and offsets.

## Reference Linux lab

PenguinBox is the reference Linux lab. Its dynamic result is the legacy LitterBox document; the `emp3r0r.telemetry/v1` adapter normalizes `findings.events` as follows:

- `collector=falco` carries `rule`, `priority`, `output_fields`, and the native `evt.type`. The rule name is the stable detection vocabulary.
- `collector=tracee` carries `eventName`, process identity, container identity, and syscall/LSM arguments.
- `coverage` lists `tracee` and `falco` as expected sensors; a run with no events from either source is incomplete.

The Linux rule profile is maintained by the lab, not by the loop. PenguinBox loads the stable Falco ruleset, the upstream incubating and sandbox rulesets, a curated container EDR profile, and a local tuning file. The tuning file disables only rules that describe the sandbox harness or duplicate another rule; it does not rename rules. The Tracee collector's default event set covers exec, file mutation, memory, network, mount and namespace, BPF, kexec, and kernel-module operations. Operators can add rule files without rebuilding the guest; the next analysis picks them up.

## Defaults and configuration

- `<workspace>/detection/labs.json` holds the Windows and Linux lab entries; missing fields use `http://127.0.0.1:1337` and `http://127.0.0.1:1338`.
- `EMP3R0R_DETECTION_LABS` selects a different labs file; `EMP3R0R_DETECTION_SANDBOX` remains a legacy URL override for both entries.
- `EMP3R0R_DETECTION_PLATFORM` selects the MCP process default platform; the loop still derives the platform from the selected module.
- `--sandbox` overrides the URL for one CLI loop.
- `/health` is authoritative for which static, dynamic, and EDR sensors are available. The plan is built from that inventory, not from a hardcoded sensor list.
- Missing sensors are recorded in `coverage.missing` and are not treated as a clean run.

Legacy LitterBox and PenguinBox result formats remain accepted for existing labs. New sensors should emit the envelope above.
