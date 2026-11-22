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

The default endpoints are `http://127.0.0.1:1337` for Windows and `http://127.0.0.1:1338` for Linux. `EMP3R0R_DETECTION_SANDBOX` overrides both. The CLI `--sandbox` flag selects one explicitly. A payload module opts into the loop with `"detection": true` in its manifest and declares its runtime platform with `"platform": "Linux"` or `"platform": "Windows"`.

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

## Defaults and configuration

- `EMP3R0R_DETECTION_SANDBOX` selects the lab URL.
- Without that variable, Windows defaults to `http://127.0.0.1:1337` and Linux defaults to `http://127.0.0.1:1338`.
- `EMP3R0R_DETECTION_PLATFORM` selects the MCP process default platform; the loop still derives the platform from the selected module.
- `--sandbox` overrides the URL for one CLI loop.
- `/health` is authoritative for which static, dynamic, and EDR sensors are available. The plan is built from that inventory, not from a hardcoded sensor list.
- Missing sensors are recorded in `coverage.missing` and are not treated as a clean run.

Legacy LitterBox and PenguinBox result formats remain accepted for existing labs. New sensors should emit the envelope above.
