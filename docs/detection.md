# Detection testing

The detection loop tests a built payload against a local
[LitterBox](https://github.com/BlackSnufkin/LitterBox) sandbox and maps every
detector hit back to the module source that produced it. The plan and run tools
cover `loader_windows` and `stager_linux` artifacts; the autonomous loop builds
`loader_windows` only. The tests run on the operator host and never touch a
target.

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

| Tool                         | Purpose                                                                                                     |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `detection_plan`             | Show the artifact, sandbox capabilities, stages, approvals, and source files a run can map to.              |
| `detection_run`              | Upload the artifact and run selected stages: `static`, `dynamic`, `edr`. Default `static`.                  |
| `detection_feedback`         | Return score, findings, source locations, pending stages, prior-run comparison, and optional analyst edits. |
| `detection_runs`             | List recorded runs, newest first, with telemetry trace and event counts.                                    |
| `detection_telemetry_import` | Import RedEdr or DefenderObserver telemetry from a local file or the configured sandbox origin.             |
| `detection_query`            | Run one read-only SELECT over the telemetry database (500 rows maximum).                                    |
| `detection_loop`             | Run the autonomous Norma loop with planner, editor, and debugger workers: build, detonate, edit source, rebuild, compare. Needs approval. |
| `detection_payloads`         | List payloads with their per-payload SQLite view, parent, score, and verdict count.                         |
| `detection_compare`          | Diff two payloads' telemetry views to show what an edit changed.                                            |
| `detection_report`           | Return the Markdown final report for one loop, including achieved objectives and edits.                     |

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

`detect_loop` in the console starts the loop. It builds a
real Go Windows agent artifact and, when `--shellcode` is omitted, wraps it with
one of the installed producer modules. `auto` builds a `windows_executable`
agent and wraps it with `donut`; `--agent-type windows_dll` builds a DLL agent,
wrapped with `crystal_pack` (Crystal Palace PICO) when that module can link on
this host, otherwise with `donut`. Agent generation and single-UUID verification
use the console's existing C2 connection. The loop then runs:

1. build `loader_windows` from `--module-dir`;
2. detonate it in LitterBox and import every saved analyzer result: RedEdr,
   Moneta, pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA, CheckPlz,
   HolyGrail, and every EDR profile;
3. run three Norma workers over SQLite and the module source: a planner that
   chooses one hypothesis, an editor that applies the source/producer edits and
   detonates one cycle, and a debugger that inspects the sandbox guest when the
   payload did not execute;
4. after the model loop finishes, run the final BOF verification exactly once. The host
   polls once per second for the last generated agent UUID, runs a small BOF
   such as `whoami`, and records the output. A check-in proves the loader reached
   the agent runtime; a non-empty BOF additionally proves the agent can run code.
   If the payload never comes online, the loop restarts with a fresh agent and
   shellcode, up to three attempts. If the agent checked in at any point, an
   inconclusive final BOF does not restart the loop and discard the completed
   cycles. A restart keeps the same logical loop and the total `--iterations` budget; the
   new attempt's prompt carries the prior attempts' last eight cycles, final
   answer and residuals, pending source edits, last executing payload, and
   source-tree hash;
5. for every dynamic cycle, use a fresh agent UUID and shellcode. The C2 pins
   the first key for each UUID (TOFU), so reusing a UUID is rejected as key
   rotation. The host enforces the rotation: before a cycle would reuse the
   active shellcode or UUID, it builds a new agent, wraps it with the active
   producer, forgets the previous UUID, and deletes the superseded agent
   executable and shellcode. The model may still call `GenerateAgent` and then
   `BuildShellcode` to choose the agent type, wrapper, or options explicitly.
   `CleanupAgent` is the explicit cleanup tool. Loop logs, reports, the
   telemetry database, and the knowledge cache are kept;
6. scope every C2 tool to the loop's own agent. `AgentStatus` checks only the
   expected UUID, `CleanupAgent` forgets only that UUID, and `RunModule` runs
   only the `whoami` verification BOF with no options. Denials and dispatches
   are written to the operator audit log;
7. after every dynamic cycle, check the cycle's generated agent with
   `AgentStatus` and record `execution=verified|offline|unverified`, the online
   flag, and the trace's network-event count in `loop_cycles` and the cycle
   summary. The host polls the C2 while the payload runs and latches the first
   check-in, so a beacon that checks in and exits before the post-run poll is
   still `verified`. An offline cycle consumes the budget but is not a
   comparable detection result: it does not count as progress. Before
   restoring, the coordinator gives the debugger worker the cycle evidence and
   lets it inspect the guest. If the debugger repairs the guest and the agent
   re-checks in, the cycle is recorded as verified with
   `recovered_by=guest-debugger` and the source is kept. Otherwise the host
   restores the editable source and active shellcode to the last payload whose
   agent checked in. If no payload has ever checked in and the debugger cannot
   repair it, the loop stops and reports the execution failure instead of
   spending more cycles on a payload that never ran;
8. write the final JSON and all cycles to the loop tables.

`--shellcode` accepts any x64 position-independent shellcode, so a Crystal
Palace/Crystal-Kit PICO from `crystal_pack` can replace the generated Donut
shellcode. Norma can change the loader, wrapper, injection path, or shellcode
producer when telemetry points at that design.

### Workers

The loop runs three independent Norma sessions, each with its own system prompt, tool set, turn cap, and optional model. The host coordinator owns the budget, no-op rejection, agent rotation, execution gate, restoration, and final report; the workers only reason and call their own tools.

| Worker | Responsibility | Tools it cannot use |
| --- | --- | --- |
| planner | Chooses one mechanism, one prediction, and the next worker. Returns one of `test`, `debug`, or `stop`. | `EditSource`, `DetectionCycle`, `BuildShellcode`, `GuestSSH` |
| editor | Applies every source/producer edit a change needs, rebuilds the agent or shellcode, then runs exactly one `DetectionCycle`. | `GuestSSH`, `AgentStatus`, `RunModule` |
| debugger | Inspects the guest over SSH when a payload did not execute or its agent did not check in. Files a source-level brief when the cause is in the module. | `EditSource`, `DetectionCycle`, `BuildShellcode`, `RevertToPayload` |

The editor may make as many `EditSource` calls as the change needs; the limit is one detonation per plan, and the host ends the editor session as soon as `DetectionCycle` returns. The planner re-plans after every completed cycle, so each hypothesis has its own mechanism and prediction. An offline cycle goes to the guest debugger before the editor does any further analysis; the editor then works from the debugger's diagnosis and brief. Worker prompts and outputs are stored in `loop_workers`; full feedback, builds, and telemetry stay in the existing tables.

Each worker step keeps one Norma session across deadline retries, empty answers, and provider failures, so a forced answer continues from the evidence already read instead of re-reading the dossier. The host enforces the worker contract: a planner that stops without a JSON plan is sent back in the same session, an editor that stops without `DetectionCycle` is sent back with the remaining edit, and a debugger that stops without its JSON object is sent back with the required schema. After 12 read-only calls the planner and editor lose their read tools until they act; `--planner-read-budget` and `--editor-read-budget` override that, and a negative value disables it. The debugger has no total tool cap by default; `--debugger-tool-budget` sets one. Mutation, build, and detonation tools are never blocked by the read budget. The host also forces the required output at the decision window and at `MaxTurns`.

`--planner-turns`, `--editor-turns`, and `--debugger-turns` default to 24, 60, and 24; `--turns` is the fallback for all three. `--worker-model` overrides the model per worker, for example `--worker-model planner=...,editor=...`. `--debugger-timeout` (default 15m) bounds one debugger pass. `--planner-read-budget` and `--editor-read-budget` default to 12 read-only calls; `--debugger-tool-budget` defaults to 0 (no total cap). A negative read budget disables that cap; turn and time limits still bound every session.

`--planner-timeout` (default 10m) is a hard decision window: when it expires, the host continues the same planner session and requires one JSON plan. `--editor-timeout` (default 15m) does the same for the editor's analysis; a running tool or `DetectionCycle` suspends it, and a completed cycle resets it. The planner and editor sessions are not restarted at the window boundary, so their reasoning and tool results survive. The debugger gets one pass per cycle; the brief reports the remaining sessions and the host refuses a second pass for the same cycle. A zero verdict or a low score is not proof of a clean payload: the sandbox may not scan the loader's injected child process, so unattributed ETW-TI and child-process telemetry remain evidence.

### Source history

`--git` (default on) records every writable source root in a shadow repository under `<store>/git/<loop>/<root>/`. It uses the pure-Go go-git library, so no git binary, hooks, or user configuration is involved; the module's own checkout and the operator's repository are never modified. The loop commits the baseline, one commit per cycle before the build (source edits only; generated files and build outputs are excluded), and a final or partial commit when it stops. Commit messages name the cycle and mechanism, each cycle summary carries `git_commits`, and the final answer carries `git_heads` and `git_dir`.

`GitHistory` returns commit messages and changed-file stats to the workers. `--git=false` disables the record.

### Guest debugging

The debugger worker is enabled only when the operator supplies the sandbox guest's SSH endpoint and key:

```bash
detect_loop --guest-ssh litterbox@127.0.0.1:2222 \
  --guest-ssh-key ~/.ssh/litterbox-vm_ed25519
```

There is no implicit host. `EMP3R0R_DETECTION_GUEST_SSH` and `EMP3R0R_DETECTION_GUEST_SSH_KEY` provide the same values. Authentication is public-key only; password authentication and agent forwarding are never used. The host key is recorded on first use in `<store>/guest_known_hosts` and fails closed on a change; `--guest-ssh-fingerprint SHA256:...` pins it instead.

`--guest-ssh-exclude` sets the debug staging directory and the Defender exclusion (default `C:\LitterBox\emp-debug`). The coordinator verifies the exclusion before every debugger session, and the debugger may also call `GuestSSH action=ensure_exclusion`; the check adds the exclusion only when it is missing. The debugger may change guest detection settings (Defender, firewall/ASR, RedEdr, analyzers) when they block execution or observation and records every change in `guest_actions`; such a cycle is debug-assisted, not a clean evasion baseline. The guest is the disposable sandbox: commands and file writes inside it are not restricted. The tool's only host-side credential is the configured SSH key; it exposes no other host paths and keeps no guest evidence on the host. The host boundary is the sandbox-only SSH key and host-key verification.

The debugger may launch a tool or artifact, kill a stuck process, read WER and Defender logs, collect a dump, and test C2 reachability from inside the guest. It cannot edit module source; when the cause is a crash or a rejected injection, it returns `source_fix_required=true` and a brief for the editor. A guest-side repair is confirmed by the host with a fresh `AgentStatus` poll, never by model text.

### Managing loops

The operator console owns the detection loops it starts.

| Command | Purpose |
| --- | --- |
| `detect_loop list [--json]` | List loops with attempt, status (`running`, `stopping`, `stopped`, `verified`, `done`, `failed`), start time, pending prompts, and log path. |
| `detect_loop stop <loop-id>` | Cancel the loop and wait up to five seconds for it to finish. Accepts the base ID or the current attempt ID. |
| `detect_loop stop --all` | Cancel every running loop. |
| `detect_loop prompt <loop-id> <instruction...>` | Append an instruction to the loop's prompt queue. The loop reads it before its next model session and includes it in the next `DetectionCycle` result. |
| `detect_loop start [options]` | Explicit launch form; `detect_loop [options]` remains the shorthand. |

The console cancels every loop when it exits. A module build already running finishes before the loop stops.

`detect_loop prompt` cannot interrupt an in-flight model turn or sandbox run. Use `detect_loop stop` to cancel the loop, or wait for the next cycle result.

### Trust model and isolation

The loop is a code-execution feature driven by an untrusted model, not a
sandbox. The model can edit module and producer source, and the builds it
triggers run on the operator host: `build.sh`, the generator it compiles, and
the source edits themselves execute with the operator's privileges. Prompt
injection from sandbox telemetry, module source, or cached knowledge can steer
those edits, so a rogue model is equivalent to code execution on the host.

> [!WARNING]
> Source-edit review, payload reversion, and the loop prompt reduce exposure but do not contain the model. `build.sh` is a required edit surface, and blocking one edit does not close the path: a `Makefile`, `config.json`, generated source, or another build input can run commands. The loop prompt is a soft guardrail against prompt injection, not a defense. Complete VM or container isolation is the only reliable boundary.

Emp3r0r cannot bound that from inside the loop. Run the loop on a dedicated,
disposable VM or container:

- give it no host credentials, no production C2 server keys, and no access to
  the operator's home directory or SSH agent;
- when the debugger is enabled, use a sandbox-only SSH key: the debugger can change guest detection settings and run commands as needed to make the payload observable, the key is its only host-side file, and it is scoped to the LitterBox guest, never a target;
- restrict egress to the model provider and the LitterBox sandbox;
- rebuild or discard the VM after a run instead of reusing a workstation;
- keep the model provider's data handling in mind: source excerpts, build logs,
  and sandbox telemetry leave the host.

The next step is to run the operator console in a disposable VM managed alongside
LitterBox, so a host-side build is no longer a trust boundary.

### Producers

`--producer name=dir` exposes a shellcode producer module to the model. The
installed `donut` and `crystal_pack` modules are added automatically. The
model may read and edit a producer's source (`EditSource module=donut`), then
call `BuildShellcode`. The `donut` module rebuilds its x86/x64 loader stubs and
generator from `core/modules/donut/src` on every build, so loader edits take
effect in the generated shellcode. `crystal_pack` rebuilds the runtime loader
objects from `core/modules/Crystal-Kit/postex-loader/src` on every build, using
`x86_64-w64-mingw32-gcc` when present and Zig's `x86_64-windows-gnu` target
otherwise. `BuildShellcode`:

- validates options against the module's `config.json` (unknown, internal, and
  out-of-choice values are rejected);
- fills the input from the agent executable next to `--shellcode` unless the
  model passes one, and requires input and decoy files to live in the operator
  payload directory;
- writes the artifact under `<store>/shellcode/<loop>/`;
- rejects non-regular or oversized output and hashes the result;
- makes the artifact the shellcode for every later cycle.

`GenerateAgent` rebuilds the Go agent itself without wrapping it. It accepts
`agent_type=windows_executable` or `windows_dll` and `arch=amd64`; the C2
address always comes from the operator configuration. The result is the agent
EXE/DLL as `artifact_path`. Call
`BuildShellcode` with `producer=donut input=<artifact_path>`, or with
`producer=crystal_pack dll=<artifact_path>` for Crystal Palace PICO shellcode;
the producer output becomes active.

For `loader_windows`, the loop rejects a cycle whose artifact is too small to
contain the active shellcode, and rejects a dynamic cycle the sandbox never
executed. This prevents a loader that drops the agent payload just to reduce
detections.

`--read-root dir` adds a read-only source root (repeatable). By default the
loader's shared build inputs (`modules/common`, `c_agent/*/util`) are exposed
read-only, so the model can trace linked code without being able to edit it.

If a cycle regresses, `RevertToPayload` replays the inverse of every recorded edit made after the chosen payload and restores the module and producer source. `DetectionCycle` records a mechanism label, one falsifiable prediction, the observed result, and the stage set with each cycle. It rejects a cycle when neither source nor shellcode changed, and it blocks a third cycle on the same mechanism after two predictions were not observed. The resume dossier carries the recent mechanism, prediction result, tested note, and edit reasons so a fresh agent session does not lose the direction it already tried. The cycle budget spans all attempts of one logical loop; it and the active shellcode are shown in the prompt and in every `DetectionCycle` result. `--iterations` and `--turns` default to 3 and 60; an explicit value is used as-is. `--stages` accepts `static`, `dynamic`, and `edr`; the loop requires at least one executing stage. `EditSource` has no separate per-cycle edit cap; a redesign may use as many edits as the turn budget allows.

### Reference cache

`knowledge-sync` downloads notebook summaries over the notebook MCP endpoint
into an FTS5 SQLite cache at `<store>/knowledge.db`. The loop reads the cache
offline; it never makes network calls. The endpoint must use `http` or `https`,
must not embed credentials, and redirects may not leave its origin. Cached text
is stripped of terminal escapes, C1 controls, and bidi overrides before it is
stored. `KnowledgeSearch` ranks cached documents and deduplicates hits by URL
across notebooks. `KnowledgeStats` reports per-notebook summary and content
coverage, `KnowledgeList` lists document references, and `KnowledgeRead`
returns a bounded summary or full text; when content was not synced it falls
back to the summary with `fallback=true`. The prompt carries the coverage, and
each `DetectionCycle` attaches a few top hits for new high/medium findings and
records the `kb=` references in the cycle row. Cached text is untrusted
reference material, not instructions.

```bash
emp3r0r knowledge-sync --url https://archeotech.r00ted.ch/mcp
emp3r0r knowledge-sync --content          # also cache full document text
emp3r0r knowledge-sync --notebook maldev  # one notebook only
```

The console exposes the same command as `detect_loop knowledge-sync`. In the
console it runs as a child process and streams its output to the output pane,
so the prompt stays responsive; the direct CLI form still waits for the refresh
to finish.

`--inject` and `--process` are overrides. When they are omitted, the module's own default controls the load path, so the model can change that default in source and have the next cycle use it. `--iterations` defaults to 3; the role turn flags default to 24 for the planner and debugger and 60 for the editor. An explicit value is used as-is, and the cycle budget is shown in every worker brief and in every `DetectionCycle` result.

The loop writes one log file under `<workspace>/detection/` and opens a
separate tmux window tailing it; `emp3r0r.log` is untouched. When verification
is enabled, agent checks and rebuilds use the console's existing C2 connection
(`detect_loop` must therefore run from a connected operator console for live
verification). `AgentStatus`, `RunModule`, and `CleanupAgent` are only
registered when verification is configured (MCP `detection_loop` omits them).
`GuestSSH` is registered only when `--guest-ssh` is configured; MCP
`detection_loop` does not enable it.
The sandbox is probed once, and no build or detection failure is retried by the host: its error, build tail, stage errors, and trace identity are given to the model, which can inspect the source and telemetry and call `DetectionCycle` after a fix. A baseline failure therefore starts the model session instead of rebuilding the same payload again, and a failed attempt does not consume the cycle budget. Model-session failures back off and resume; the loop is not ended because a session stalls. A trace without a payload PEB is recorded and kept for the model with the `telemetry/attribution` finding instead of being detonated again. One build/detonate/verify cycle is bounded by `--cycle-timeout` (default 60m). A session that completes no cycle within that deadline is stopped and the model must apply an edit and retry; the loop continues. One model session is bounded by `--session-timeout` (default 2h), and a session with no tool call by `--tool-idle-timeout` (default 30m). An in-flight tool suspends the idle check and an in-flight cycle is bounded by its own deadline. `--timeout 0` (the default) means no loop-wide deadline. A final answer that is not the requested JSON object is stored as the summary with `parse_error` instead of ending the run. The loop writes the full Markdown report to `<workspace>/detection/reports/<loop>.md` and a compact executive summary to `<loop>-summary.md`, emits the full report through the tmux log pane when the loop finishes, and stores the report in `loop_results.report`. If the loop is stopped or fails before the final answer, it writes a partial report and summary from the cycles completed so far. The operator console prints the rendered executive summary, not the raw report.

Loop timestamps use local time. A `[progress]` heartbeat is written every two
minutes with elapsed time, cycles used, tool calls, sessions, last execution
state, and the expected agent UUID, so a long model session is visibly alive.

Loop log lines are tagged and colored by category: model thinking is dimmed,
model text, thinking, and final answers are rendered as Markdown, tool calls and
results stay raw for grepping, and builds, edits, cycles, warnings, and errors
each get their own tag color. The tmux pane colors the plain tags with `awk`;
the on-disk log stays plain text without ANSI or heading markers. Markdown width
follows the tmux log pane or the terminal running the console; `COLUMNS` is
honored when no terminal size is available, with a 120-column fallback. The
final report is rendered from Markdown for the terminal before it is logged;
the on-disk report stays Markdown. `NO_COLOR=1` or `TERM=dumb` disables
colors.

Model credentials can be exported in the shell, or put in the operator
environment file at `<workspace>/operator.env` (mode `0600`):

```bash
EMP3R0R_DETECTION_PROVIDER=openai-responses
EMP3R0R_DETECTION_MODEL=<model>
EMP3R0R_DETECTION_BASE_URL=<url>
OPENAI_API_KEY=<key>
```

The console client and MCP server load that file at startup.
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
- `signal`: `signal`, `verdict`, `scan`, `info`, `unattributed`, `baseline`, or
  `noise`.
- Ambient instrument images such as `RedEdrDll.dll`, `LitterBox\Scanners`, and
  MSVC runtimes are stored as `signal=noise`. The feedback view and the
  actionable-finding check skip them, so they cannot trigger another cycle.
- An event whose payload attribution failed but whose operation is
  high-value—ETW-TI memory write/protect/map/allocate or process creation—is
  stored as `signal=unattributed`, not `noise`. Unattributed ETW-TI memory
  operations produce low-severity `telemetry/unattributed-etwti` findings with
  the operation, protection, region count, largest size, and PID, and
  unattributed process creation produces `telemetry/unattributed-process`. The
  loop can therefore inspect them even when the trace has no payload PEB.
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

| Table             | Columns                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `payloads`        | one row per artifact: `payload_key`, `sha256`, `module`, `label`, `table_name`, `parent_id`                                                                                                                                                                                                                                                                                                                                                 |
| `traces`          | `id`, `payload_id`, `run_id`, `external_id`, `module`, `artifact_sha256`, `source`, `captured_at`, `path`, `meta`, `payload_pid`, `payload_image`, `attribution`, `coverage`, `event_count`, `findings_count`                                                                                                                                                                                                                               |
| `events`          | `id`, `payload_id`, `trace_pk`, `event_key`, `ts_ns`, `type`, `source`, `event`, `provider`, `event_id`, `pid`, `tid`, `actor_pid`, `target_pid`, `target_tid`, `parent_pid`, `operation`, `process`, `target_image`, `path`, `image`, `address`, `size`, `protection`, `access`, `status`, `command`, `proto`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `bytes`, `stack`, `category`, `severity`, `signal`, `payload_role`, `attrs` |
| `findings`        | `trace_pk`, `payload_id`, `stage`, `tool`, `severity`, `rule`, `indicator`, `detail`, `signal`                                                                                                                                                                                                                                                                                                                                              |
| `loop_cycles`     | `loop_id`, `iteration`, `payload_id`, `run_id`, `score`, `level`, `findings`, `verdicts`, `trace_id`, `summary`                                                                                                                                                                                                                                                                                                                             |
| `loop_feedback`   | full feedback JSON per cycle                                                                                                                                                                                                                                                                                                                                                                                                                |
| `loop_builds`     | full build log per cycle                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `loop_edits`      | `payload_id` before the edit, `next_payload_id` it produced, `module`, `file`, `old`, `new`, `reason`                                                                                                                                                                                                                                                                                                                                       |
| `loop_shellcodes` | producer, path, SHA-256, size, options, and iteration for every generated shellcode                                                                                                                                                                                                                                                                                                                                                         |
| `cycle_history`   | view over `loop_cycles` and `payloads`: `loop_id`, `iteration`, `payload_id`, `payload_key`, `run_id`, `score`, `level`, `findings`, `verdicts`, `trace_id`, `executed`, `execution`, `agent_online`, `network_events`, `summary`, `created_at`                                                                                                                                                                                           |
| `payload_view`    | view over `payloads` and the latest trace: `payload_id`, `payload_key`, `sha256`, `module`, `label`, `artifact_path`, `table_name`, `parent_id`, `created_at`, `trace_id`, `trace_run_id`, `trace_attribution`                                                                                                                                                                                                                               |

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
