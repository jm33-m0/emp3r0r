# Detection testing

The detection loop tests a built payload against a local
[LitterBox](https://github.com/BlackSnufkin/LitterBox) sandbox and maps every
detector hit back to the module source that produced it. It covers
`loader_windows` and `stager_linux` artifacts; the tests run on the operator
host and never touch a target.

## Prerequisites

- A reachable LitterBox API. The default is `http://127.0.0.1:1337`. Set
  `EMP3R0R_DETECTION_SANDBOX` to use another URL.
- The sandbox reports its scanners and EDR profiles through `/health`; a
  scanner that is missing or disabled is omitted from the plan.

## Build-time behavior

A successful `run_module loader_windows` or `run_module stager_linux` returns a
`detection` block next to the build log:

- the artifact path, size, and SHA-256;
- the plan and every stage;
- the passive static run, if the sandbox is reachable;
- `run_id`, risk score, finding count, and source-edit pointers.

Passive static analysis runs automatically. Dynamic and EDR stages detonate the
payload, so they are planned but never started by a build. If the sandbox is
unreachable, the block says `sandbox-unavailable` and carries the plan;
`detection_plan` rebuilds it once the sandbox is reachable.

## MCP tools

| Tool                 | Purpose                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| `detection_plan`     | Show the artifact, sandbox capabilities, stages, approvals, and source files a run can map to. |
| `detection_run`      | Upload the artifact and run selected stages: `static`, `dynamic`, `edr`. Default `static`.     |
| `detection_feedback` | Return score, findings, source locations, pending stages, prior-run comparison, and optional analyst edits. |
| `detection_runs`     | List recorded runs, newest first, with telemetry trace and event counts.                       |
| `detection_telemetry_import` | Import RedEdr or DefenderObserver telemetry from a local file or the configured sandbox origin. |
| `detection_query`    | Run one read-only SELECT over the telemetry database (500 rows maximum).                      |
| `detection_loop`     | Run the autonomous Norma loop: build, detonate, edit source, rebuild, compare. Needs approval. |
| `detection_payloads` | List payloads with their per-payload SQLite view, parent, score, and verdict count.           |
| `detection_compare`  | Diff two payloads' telemetry views to show what an edit changed.                               |
| `detection_report`   | Return the Markdown final report for one loop, including achieved objectives and edits.        |

Only artifacts recorded from a build of the named module can be uploaded.
Pass `artifact` to select an older build; omit it to use the newest.

`dynamic` and `edr` require `approve_execution=true`. Without it the stage is
skipped and reported as pending. `edr_profile` narrows the run to one profile;
omit it to run every configured profile.

## Feedback

Feedback maps each indicator to a module file, line, and column:

- YARA matches identify the rule and the matched bytes;
- string, network, path, registry, and function indicators come from the static
  analyzers;
- dynamic scanner and EDR alert text is mapped by API and technique names.

A detection with no literal source match is reported as such; it can come from
a dependency, a toolchain default, or generated build data. Pending stages make
the feedback partial and are listed explicitly.

Edit the workspace module copy, rebuild with `run_module`, then run
`detection_run` on the new artifact. `detection_feedback` reports the previous
artifact of the same module, the score delta, resolved indicators, and new
indicators. Keep the module contract described in
`docs/module_development_guide.md`.

## Autonomous loop

`detect_loop` in the console starts a detached worker. It generates a real Go
Windows agent shellcode when `--shellcode` is omitted, then runs:

1. build `loader_windows` from `--module-dir`;
2. detonate it in LitterBox and import every saved analyzer result: RedEdr,
   Moneta, pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA, CheckPlz,
   HolyGrail, and every EDR profile;
3. let a Norma agent query SQLite, edit module source, rebuild, and compare
   payloads;
4. write the final JSON and all cycles to the loop tables.

`--shellcode` accepts any x64 position-independent shellcode, so a Crystal
Palace/Crystal-Kit PICO from `crystal_pack` can replace the generated Donut
shellcode. Norma can change the loader, wrapper, injection path, or shellcode
producer when telemetry points at that design.

### Trust model and isolation

The loop is a code-execution feature driven by an untrusted model, not a
sandbox. The model can edit module and producer source, and the builds it
triggers run on the operator host: `build.sh`, the generator it compiles, and
the source edits themselves execute with the operator's privileges. Prompt
injection from sandbox telemetry, module source, or cached knowledge can steer
those edits, so a rogue model is equivalent to code execution on the host.

Emp3r0r cannot bound that from inside the loop. Run the loop on a dedicated,
disposable VM or container:

- give it no host credentials, no production C2 server keys, and no access to
  the operator's home directory or SSH agent;
- restrict egress to the model provider and the LitterBox sandbox;
- rebuild or discard the VM after a run instead of reusing a workstation;
- keep the model provider's data handling in mind: source excerpts, build logs,
  and sandbox telemetry leave the host.

The next step is to run the worker itself in a disposable VM managed alongside
LitterBox, so a host-side build is no longer a trust boundary.

### Producers

`--producer name=dir` exposes a shellcode producer module to the model. The
installed `donut` and `crystal_pack` modules are added automatically. The
model may read and edit a producer's source (`EditSource module=donut`), then
call `BuildShellcode`. The `donut` module rebuilds its x86/x64 loader stubs and
generator from `core/modules/donut/src` on every build, so loader edits take
effect in the generated shellcode. `BuildShellcode`:

- validates options against the module's `config.json` (unknown, internal, and
  out-of-choice values are rejected);
- fills the input from the agent executable next to `--shellcode` unless the
  model passes one, and requires input and decoy files to live in the operator
  payload directory;
- writes the artifact under `<store>/shellcode/<loop>/`;
- rejects non-regular or oversized output and hashes the result;
- makes the artifact the shellcode for every later cycle.

`--read-root dir` adds a read-only source root (repeatable). By default the
loader's shared build inputs (`modules/common`, `c_agent/*/util`) are exposed
read-only, so the model can trace linked code without being able to edit it.

If a cycle regresses, `RevertToPayload` replays the inverse of every recorded
edit made after the chosen payload and restores the module and producer source.
The cycle budget and the active shellcode are shown in the prompt and in every
`DetectionCycle` result; `--iterations` is capped at 50 and `--turns` at 240.

### Reference cache

`knowledge-sync` downloads notebook summaries over the notebook MCP endpoint
into an FTS5 SQLite cache at `<store>/knowledge.db`. The loop reads the cache
offline; it never makes network calls. The endpoint must use `http` or `https`,
must not embed credentials, and redirects may not leave its origin. Cached text
is stripped of terminal escapes, C1 controls, and bidi overrides before it is
stored. `KnowledgeSearch` ranks cached documents
and `KnowledgeRead` returns a bounded summary or full text. Cached text is
untrusted reference material, not instructions.

```bash
emp3r0r knowledge-sync --url https://archeotech.r00ted.ch/mcp
emp3r0r knowledge-sync --content          # also cache full document text
emp3r0r knowledge-sync --notebook maldev  # one notebook only
```

The console exposes the same command as `detect_loop knowledge-sync`.

`--inject` and `--process` are overrides. When they are omitted, the module's
own default controls the load path, so the model can change that default in
source and have the next cycle use it. `--iterations` and `--turns` are not
capped by the loop; the values you pass are the values it uses, and the cycle
budget is shown in the prompt and in every `DetectionCycle` result.

The worker writes one log file under `<workspace>/detection/` and opens a
separate tmux window tailing it; `emp3r0r.log` is untouched. It does not need
MCP or a C2 connection. Transient sandbox, build, detection, and agent-session
failures are retried with exponential backoff; the worker does not exit on
them. `--timeout 0` (the default) means no deadline. A final answer that is not
the requested JSON object is stored as the summary with `parse_error` instead
of ending the run. The worker writes the human-readable Markdown report to
`<workspace>/detection/reports/<loop>.md`, emits it through the console log
pane when the worker exits, and stores it in `loop_results.report`.

Loop log lines are tagged and colored by category: model thinking is dimmed,
model text uses the terminal default, tool calls, tool results, builds, edits,
cycles, warnings, and errors each get their own tag color. The final report is
rendered from Markdown for the terminal before it is logged; the on-disk report
stays Markdown. `NO_COLOR=1` or `TERM=dumb` disables colors.

Model credentials can be exported in the shell, or put in the operator
environment file at `<workspace>/operator.env` (mode `0600`):

```bash
EMP3R0R_DETECTION_PROVIDER=openai-responses
EMP3R0R_DETECTION_MODEL=<model>
EMP3R0R_DETECTION_BASE_URL=<url>
OPENAI_API_KEY=<key>
```

The console client, MCP server, and detached worker load that file at startup.
A variable already present in the process environment wins; the file never
overrides an explicit shell export. Set `EMP3R0R_OPERATOR_ENV` to load a
different path. Full-line comments, `export KEY=value`, and quoted values are
accepted; shell expansion is not performed.

```bash
detect_loop --module-dir /path/to/core/modules/loader_windows --iterations 3
```

The MCP equivalents are `detection_loop` (requires `approve_execution=true`),
`detection_payloads`, and `detection_compare`.

The agent context contains instructions and bounded tool results only. Full
feedback, build logs, and per-payload telemetry stay in SQLite; Norma queries
them by payload view or `trace_pk`.

## Telemetry database

`detection_run` imports every saved sandbox result into SQLite at
`<workspace>/detection/telemetry.db` and attaches the trace ID and
deterministic findings to the run. RedEdr events keep their normalized rows;
the other analyzers become `type='analysis'` events with the analyzer JSON in
`attrs`, so a model can query them without a second sandbox run. The import
covers:

- file info and static YARA, CheckPlz, and Stringnalyzer output;
- dynamic RedEdr, Moneta, pe-sieve, HollowsHunter, HSB, Patriot, Blender,
  YARA, and CheckPlz output;
- HolyGrail BYOVD output and every saved EDR profile result.

`detection_telemetry_import` additionally accepts offline RedEdr JSON arrays or
JSONL, including the `raw_output` embedded in a LitterBox dynamic result,
DefenderObserver JSONL (`timestamp`, `providerName`, `id`, `payload`), and a
LitterBox result that nests `rededr.findings`.

`detection_telemetry_import` accepts `path` or `url` plus optional `module`,
`artifact`, `run_id`, and `source`. A `url` must use the configured LitterBox
origin, and redirects may not leave it; save remote telemetry locally and pass
`path` instead. `detection_run` imports every saved sandbox result
automatically when a selected stage completes.

Every JSON event from RedEdr is stored, including `findings.events`,
`raw_output`, kernel callbacks, ntdll hooks, PEB and loaded-DLL queries, ETW-TI
memory operations, and Defender behavior. The importer merges those sources
and deduplicates by trace/id. Each event gets actor and target identities,
operation, source coverage, payload attribution, and a signal class:

- `payload_role`: `payload`, `payload-child`, `payload-target`, `payload-scan`,
  `ambient`, or `unknown`.
- `signal`: `signal`, `verdict`, `scan`, `info`, `baseline`, or `noise`.
- `category`: `process`, `image`, `module`, `file`, `network`, `audit`, `thread`,
  `defender`, `query`, `hook`, `memory` (ETW-TI), `analysis`, or `other`.

Payload attribution comes from the PEB query. A trace that never observed the
payload PEB is marked `unknown` instead of attributing Defender traffic to the
sample. `traces.coverage` records which sources delivered events and which
enabled sources produced none.

The deterministic findings cover every category, including cross-process
ETW-TI writes/protects/suspends, self-modifying memory, kernel and ntdll hooks,
audit API calls, child processes, user-writable images and modules, file
writes, network flows, Defender verdicts, and sandbox analyzers that report
high or medium findings (`rule = analyzer/<analyzer>`). The findings are materialized in
the `findings` table. The loop treats a finding as actionable only when it maps
to module source or is a real verdict; unmatched findings are reported as
residuals instead of driving another cycle. Analyzer status and errors are
recorded in `traces.coverage.analyzers` and surface as `coverage.missing`
entries, so a failed scan is never reported as a clean cycle. A zero verdict
count is not treated as safe; actionable high/medium findings remain until the
cycle budget is exhausted, with inherent items recorded as residuals.

Schema:

| Table | Columns |
| --- | --- |
| `payloads` | one row per artifact: `payload_key`, `sha256`, `module`, `label`, `table_name`, `parent_id` |
| `traces` | `id`, `payload_id`, `run_id`, `external_id`, `module`, `artifact_sha256`, `source`, `captured_at`, `path`, `meta`, `payload_pid`, `payload_image`, `attribution`, `coverage`, `event_count`, `findings_count` |
| `events` | `id`, `payload_id`, `trace_pk`, `event_key`, `ts_ns`, `type`, `source`, `event`, `provider`, `event_id`, `pid`, `tid`, `actor_pid`, `target_pid`, `target_tid`, `parent_pid`, `operation`, `process`, `target_image`, `path`, `image`, `address`, `size`, `protection`, `access`, `status`, `command`, `proto`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `bytes`, `stack`, `category`, `severity`, `signal`, `payload_role`, `attrs` |
| `findings` | `trace_pk`, `payload_id`, `stage`, `tool`, `severity`, `rule`, `indicator`, `detail`, `signal` |
| `loop_cycles` | `loop_id`, `iteration`, `payload_id`, `run_id`, `score`, `level`, `findings`, `verdicts`, `trace_id`, `summary` |
| `loop_feedback` | full feedback JSON per cycle |
| `loop_builds` | full build log per cycle |
| `loop_edits` | `payload_id` before the edit, `next_payload_id` it produced, `module`, `file`, `old`, `new`, `reason` |
| `loop_shellcodes` | producer, path, SHA-256, size, options, and iteration for every generated shellcode |

Every payload gets its own SQLite view named `payload_<hash>`; the name is in
`payloads.table_name`. This is the one-payload-per-table query surface: query
the view to see only that build's events, and compare two payload views to see
exactly what a source edit added or removed. The raw tables keep one normalized
copy, so views do not duplicate storage.

```sql
SELECT payload_key, table_name, parent_id, score, verdicts
FROM payloads ORDER BY id DESC;

-- What this payload did
SELECT category, event, count(*) FROM payload_<hash> GROUP BY category, event;
```

`loop_edits.next_payload_id` links each edit to the build it produced; query it
with the payload row to explain every change.

`events.attrs` is the original event object; use `json_extract` for fields that
have no dedicated column. `events.signal` and `events.payload_role` are the
fast filter for “is this the payload acting” and “is this worth investigating”.
The `findings` table is the materialized result of the same attribution, so a
model can read findings without replaying every event.

`detection_query` and the analyst's `TelemetryQuery` accept one `SELECT` or
`WITH` statement. Comments, semicolons inside the statement, PRAGMAs, ATTACH,
and every write or schema keyword are rejected; queries run on a read-only
connection with a 15-second bound and at most 500 rows.

Useful checks:

```sql
-- What the payload did, by category and event
SELECT category, event, count(*) AS n
FROM events WHERE trace_pk = 1 GROUP BY category, event ORDER BY n DESC;

-- Child processes and the raw child PID
SELECT pid, image, json_extract(attrs, '$.processid') AS child_pid
FROM events WHERE trace_pk = 1 AND category = 'process';

-- Files created by the payload outside Windows
SELECT event, path FROM events
WHERE trace_pk = 1 AND category = 'file' AND pid = 1234
  AND path NOT LIKE '%\Windows\%';

-- ETW-TI memory operations with caller and target
SELECT operation, pid AS caller, target_pid, target_image, count(*),
       max(size), max(bytes), max(protection)
FROM events WHERE trace_pk = 1 AND category = 'memory'
GROUP BY operation, pid, target_pid, target_image;

-- ntdll hooks and kernel callbacks
SELECT category, event, pid, target_pid, protection, status, stack
FROM events WHERE trace_pk = 1 AND category IN ('hook', 'thread');

-- Payload network flows; ambient Defender flows are excluded
SELECT proto, src_addr, src_port, dst_addr, dst_port, bytes
FROM events WHERE trace_pk = 1 AND category = 'network'
  AND payload_role IN ('payload', 'payload-child');

-- Defender verdicts versus scan activity
SELECT severity, signal, event, path, detail
FROM events WHERE trace_pk = 1 AND category = 'defender'
ORDER BY id;

-- Materialized findings, including ETW-TI and hook rules
SELECT severity, rule, indicator, detail FROM findings
WHERE trace_pk = 1 ORDER BY severity, rule;
```

A real verdict is an event such as `Behavior Monitoring BmDetection` with a
`name` such as `Behavior:Win32/SvchostInject.A`. `BmModuleLoad`,
`BmNotificationHandle*`, and `Cache*` are scan activity, not verdicts. The
sandbox risk score also treats some non-verdict strings as threats; read the
telemetry rows before trusting a risk factor.

## Analyst

`detection_feedback analyze=true` asks a read-only agent for proposed edits.
It can list, read, and search the module source; it cannot write. The agent
runs on [Norma](https://github.com/Autumn-27/norma) and is configured through
environment variables:

| Variable                               | Meaning                                                        |
| -------------------------------------- | -------------------------------------------------------------- |
| `EMP3R0R_DETECTION_PROVIDER`           | `anthropic` (default), `openai`, or `openai-responses`.        |
| `EMP3R0R_DETECTION_MODEL`              | Model name. Falls back to `ANTHROPIC_MODEL` or `OPENAI_MODEL`. |
| `EMP3R0R_DETECTION_BASE_URL`           | Optional provider base URL.                                    |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Provider credential.                                           |

Without a model and its credential, the tool returns deterministic feedback and
an `analysis_error`; the loop still works.

The analyst sends sandbox findings and the source excerpts it reads to the
configured model endpoint. Disable it by leaving the model and key unset.

## Storage

Plans, runs, telemetry, and the artifact registry live under
`<workspace>/detection` (`~/.emp3r0r/detection` by default). Directories are
`0700` and files are `0600`. Dynamic runs add `telemetry.db` (WAL mode) next to
the run records.
Feedback is derived from the stored run, so a run can be inspected without
detonating the payload again.
