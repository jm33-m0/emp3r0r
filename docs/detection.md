# Detection testing

The detection loop tests a built payload against a local sandbox and maps every
detector hit back to the module source that produced it. Windows payloads run in
[LitterBox](https://github.com/BlackSnufkin/LitterBox); Linux payloads run in
PenguinBox, a LitterBox-compatible Linux VM that exposes Tracee and Falco
telemetry. The plan and run tools cover `loader_windows` and `stager_linux`
artifacts, and the autonomous loop builds both. The tests run on the operator
host and never detonate on a target.

The lab API and the sensor-neutral `emp3r0r.telemetry/v1` envelope are specified in [detection_lab.md](detection_lab.md).

## Prerequisites

- Both lab endpoints live in one operator file,
  `<workspace>/detection/labs.json` (`~/.emp3r0r/detection/labs.json` by
  default). The Windows lab defaults to `http://127.0.0.1:1337` and the Linux
  lab to `http://127.0.0.1:1338`; each entry can override its URL and guest
  SSH settings:
  ```json
  {
    "windows": {
      "url": "http://127.0.0.1:1337",
      "guest_ssh": "litterbox@127.0.0.1:2222",
      "guest_ssh_key": "~/.ssh/litterbox-vm_ed25519"
    },
    "linux": {
      "url": "http://127.0.0.1:1338",
      "guest_ssh": "penguinbox@127.0.0.1:2223",
      "guest_ssh_key": "~/penguinbox/storage/penguinbox/ssh/id_ed25519"
    }
  }
  ```
  The MCP server reads it at startup and the console reads it for each new loop; restart the MCP server after editing it.
  `EMP3R0R_DETECTION_LABS` overrides the path and
  `EMP3R0R_DETECTION_SANDBOX` remains a legacy global URL override.
- A Linux lab needs the PenguinBox API, normally through its SSH tunnel. It
  reports Tracee and Falco under dynamic scanners and has no EDR profiles.
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
| `detection_telemetry_import` | Import RedEdr or DefenderObserver telemetry from a file under the detection store or a configured sandbox origin.             |
| `detection_query`            | Run one read-only SELECT over the telemetry database (500 rows maximum).                                    |
| `detection_loop`             | Run the autonomous Norma loop with planner, editor, and debugger workers: build, detonate, edit source, rebuild, compare. Needs approval. |
| `detection_payloads`         | List payloads with their per-payload SQLite view, parent, score, and verdict count.                         |
| `detection_compare`          | Diff two payloads' telemetry views to show what an edit changed.                                            |
| `detection_report`           | Return the Markdown final report for one loop: high/static finding counts, a finding-to-change map with the first cycle and edit where each baseline finding stopped appearing, per-role token usage and estimated cost, and the detailed edit log. |

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

`detect_loop` in the console starts the loop. `--module` selects the payload:
`loader_windows` (default) or `stager_linux`. The platform is derived from the
module; `--module-dir` defaults to the installed module path.

For `loader_windows` the loop builds a real Go Windows agent artifact and, when
`--shellcode` is omitted, wraps it with one of the installed producer modules.
`auto` builds a `windows_executable` agent and wraps it with `donut`;
`--agent-type windows_dll` builds a DLL agent, wrapped with `crystal_pack`
(Crystal Palace PICO) when that module can link on this host, otherwise with
`donut`. Agent generation and single-UUID verification use the console's
existing C2 connection.

For `stager_linux` the loop builds a fresh C agent shared object from the
editable `c_agent` tree (default: the sibling `core/c_agent`), wraps it with the
editable malasada producer, and embeds the PIC in an executable `stager_linux`
build. The default C agent build uses glibc 2.17 and `DYNLOAD_MODE=auto`, so the
same artifact loads `libcrypto`/`libcurl` on older and current glibc hosts. Both the C agent and malasada are writable source roots, so agent and
wrapper edits are part of the payload under test. `--agent-type` is always
`linux_so`; the host fixes `format=executable`, and raw, packed, shared-object,
`inject`, `smw`, and the Windows-specific guest-defense paths do not apply. The operator
kit ships the pinned Go toolchain under `lib/emp3r0r/go` and the editable Go
agent source under `lib/emp3r0r/go_agent` with its `build.py`, so malasada
rebuilds and Windows Go agents are generated on demand. The workspace mirrors
`go_agent` next to `c_agent`, making the Go source a writable loop root. The sandbox executes
the ELF in a PenguinBox guest, and the loop imports Tracee syscall/LSM events and
Falco alerts. The tests run on the operator host and never touch a target.

The loop then runs:

1. build the selected module from `--module-dir` as an executable payload;
2. detonate it in the selected sandbox and import every saved result. Windows
   imports RedEdr, Moneta, pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA,
   CheckPlz, HolyGrail, and every EDR profile. Linux imports Tracee events,
   Falco alerts, ELF findings, and YARA matches;
3. run three Norma workers over SQLite and the module source: a planner that
   chooses one hypothesis, an editor that applies the source/producer edits and
   detonates one cycle, and a debugger that inspects the sandbox guest when the
   payload did not execute; by default the debugger runs once at the final stop
   (`--debugger-policy final`);
4. after the model loop finishes, verify the last generated agent UUID exactly
   once. The host polls once per second and treats a live C2 check-in as proof
   that the loader reached the agent runtime. It does not require a verification
   BOF: LitterBox terminates the beacon at the capture boundary, so a BOF may
   never run. If the payload never comes online, the loop restarts with a fresh
   agent and shellcode, up to three attempts. If the agent checked in at any
   point, a missing BOF result does not restart the loop and discard the
   completed cycles. A restart keeps the same logical loop and the total `--iterations` budget; the
   new attempt's prompt carries the prior attempts' last eight cycles, final
   answer and residuals, pending source edits, last executing payload, and
   source-tree hash;
5. for every dynamic cycle, use a fresh agent UUID and payload. The C2 pins
   the first key for each UUID (TOFU), so reusing a UUID is rejected as key
   rotation. The host enforces the rotation: before a cycle would reuse the
   active shellcode or UUID, it builds a new agent, wraps it with the active
   producer, forgets the previous UUID, and deletes the superseded agent
   executable and shellcode. The model may still call `GenerateAgent` and then
   `BuildShellcode` to choose the agent type, wrapper, or options explicitly.
   Producer build options, including Crystal Palace `link_options`, persist for the active producer and are reused when the host rotates the agent.
   `CleanupAgent` is the explicit cleanup tool. Loop logs, reports, the
   telemetry database, and the knowledge cache are kept;
6. scope every C2 tool to the loop's own agent. `AgentStatus` checks only the
   expected UUID, `CleanupAgent` forgets only that UUID, and `RunModule` runs
   only the `whoami` verification BOF with no options as a diagnostic, not as a
   health signal. Denials and dispatches
   are written to the operator audit log;
7. after every dynamic cycle, check the cycle's generated agent with
   `AgentStatus` and record `execution=verified|offline|unverified`, the online
   flag, and the trace's network-event count in `loop_cycles` and the cycle
   summary. The host polls the C2 while the payload runs and latches the first
   check-in, so a beacon that checks in and exits before the post-run poll is
   still `verified`. An offline cycle consumes the budget but is not a
   comparable detection result: it does not count as progress. The host
   restores the editable source and active shellcode to the last clean
   verified baseline. `--debugger-policy cycle` adds a guest pass after every
   non-executing cycle; `final` (the default) reserves one pass for the stop
   decision, and `off` disables it. A payload that the debugger relaunches
   manually can re-check in, but the cycle stays `offline` with
   `recovered_by=guest-debugger`: a manual run does not turn an
   unattributed trace into a finding baseline, and the source is not kept. A
   verified cycle that raises a real verdict, high findings, static
   signatures, or total findings is recorded and reported to the planner
   instead of becoming the new baseline; the host keeps its source edits so
   the next cycle can build on the parts that worked and change only the part
   that raised the regressed count. A verdict change is compared before the
   weighted finding score: losing a verdict is progress even when the medium
   count rises, and gaining one is a regression even when the weighted score
   improves. If no payload has ever checked in and the debugger cannot repair
   it, the loop stops and reports the execution failure instead of spending
   more cycles on a payload that never ran;
8. write the final JSON and all cycles to the loop tables.

`--shellcode` accepts any x64 position-independent shellcode, so a Crystal
Palace/Crystal-Kit PICO from `crystal_pack` can replace the generated Donut
shellcode. Norma can change the loader, wrapper, injection path, or shellcode
producer when telemetry points at that design.

### Workers

The loop runs three independent Norma sessions, each with its own system prompt, tool set, turn cap, and optional model. The host coordinator owns the budget, no-op rejection, agent rotation, execution gate, restoration, and final report; the workers only reason and call their own tools.

| Worker | Responsibility | Tools it cannot use |
| --- | --- | --- |
| planner | Chooses one mechanism, one prediction, and the next worker. Returns one of `test`, `debug`, or `stop`. | `EditSource`, `BuildOptions`, `DetectionCycle`, `BuildShellcode`, `GuestSSH` |
| editor | Applies every source/producer edit a change needs, rebuilds the agent or shellcode, then runs exactly one `DetectionCycle`. | `GuestSSH`, `AgentStatus`, `RunModule` |
| debugger | Inspects the guest over SSH when a payload did not execute or its agent did not check in. Files a source-level brief when the cause is in the module. | `EditSource`, `BuildOptions`, `DetectionCycle`, `BuildShellcode`, `RevertToPayload` |

The editor may make as many `EditSource` calls as the change needs; the limit is one detonation per plan, and the host ends the editor session as soon as `DetectionCycle` returns. The planner re-plans after every completed cycle, so each hypothesis has its own mechanism and prediction. With `--debugger-policy cycle`, an offline cycle goes to the guest debugger before the editor does further analysis; with `final` (the default), the host restores the last clean verified baseline and reserves the debugger for the stop decision. Worker prompts and outputs are stored in `loop_workers`; full feedback, builds, and telemetry stay in the existing tables.

Each worker step keeps one Norma session across deadline retries, empty answers, and provider failures, so a forced answer continues from the evidence already read instead of re-reading the dossier. The host enforces the worker contract: a planner that stops without a JSON plan is sent back in the same session, an editor that stops without `DetectionCycle` is sent back with the remaining edit, and a debugger that stops without its JSON object is sent back with the required schema. After 12 read-only calls the planner and editor lose their read tools until they act; `--planner-read-budget` and `--editor-read-budget` override that, and a negative value disables it. The debugger has no total tool cap by default; `--debugger-tool-budget` sets one. Mutation, build, and detonation tools are never blocked by the read budget. The host also forces the required output at the decision window and at `MaxTurns`.

Old read-only detection tool results (`SourceRead`, `SourceSearch`, `TelemetryQuery`, `GuestSSH`, knowledge, payload, and git reads) are cleared once a session reaches Norma's micro-compaction threshold; edit, build, and cycle results are kept, and the conversation summary still runs at the same threshold.

`--planner-turns`, `--editor-turns`, and `--debugger-turns` default to 24, 60, and 24; `--turns` is the fallback for all three. `--worker-model` overrides the model per worker, for example `--worker-model planner=...,editor=...`. `--debugger-timeout` (default 15m) bounds one debugger pass. `--debugger-policy` selects `final` (default), `cycle`, or `off`. `--planner-read-budget` and `--editor-read-budget` default to 12 read-only calls; `--debugger-tool-budget` defaults to 0 (no total cap). A negative read budget disables that cap; turn and time limits still bound every session. `--input-price`, `--output-price`, `--cache-read-price`, and `--cache-write-price` set the USD-per-million-token rates used by the progress heartbeat and the final report; unset rates leave the exact token counts without a dollar estimate.

`--planner-timeout` (default 10m) is a hard decision window: when it expires, the host continues the same planner session and requires one JSON plan. `--editor-timeout` (default 15m) does the same for the editor's analysis; a running tool or `DetectionCycle` suspends it, and a completed cycle resets it. The planner and editor sessions are not restarted at the window boundary, so their reasoning and tool results survive. With `--debugger-policy cycle`, the debugger gets one pass per cycle and the host refuses a second pass for the same cycle; with `final`, it gets one pass at the stop. A zero verdict or a low finding count is not proof of a clean payload: the sandbox may not scan the loader's injected child process, so unattributed ETW-TI and child-process telemetry remain evidence.

### Build options

For `stager_linux`, `BuildOptions` changes the stager's declared transport, unpacker, sleep mask, dynload mode, hash style, ECH, and supervision options. The host fills `agent-pic` and fixes `format=executable`, because PenguinBox executes the ELF directly. Agent behavior is changed in the writable C agent root (`--agent-source-dir`, default the sibling `c_agent`); call `GenerateAgent` after those edits to build a fresh `linux_so`, then `BuildShellcode producer=malasada input=<artifact_path>` to produce the PIC with a new UUID. For `loader_windows`, the same flag selects the editable Go agent root; the default is the sibling `go_agent`, and `GenerateAgent` compiles it on demand. The malasada module is editable like donut, so the loop can change its ELF patching or compression when telemetry points at the wrapper.

A Linux cycle uses the mechanisms `stager`, `agent`, `producer`, `build-flags`, `static-hygiene`, or `other`. The producer mechanism edits the editable malasada source; `BuildShellcode producer=malasada input=<artifact_path>` rebuilds it. The debugger has `AgentStatus`, `CleanupAgent`, and `GuestSSH` for the PenguinBox guest over bash; `RunModule` and the Windows BOF path are absent.

`BuildOptions` lists the payload module's declared build options, sets them, or resets them to the module default. The editor can change `format`, `inject`, `process`, `process-args`, `smw`, `verify-ms`, and `key` for `loader_windows`; the host fills `shellcode`, `output`, and `arch`. A build-option change is a complete change for `DetectionCycle`, so it does not need a source edit, and the effective values are recorded in every cycle summary. The execution gate and `RevertToPayload` restore the last executing build options with the source and shellcode. For a producer, `BuildShellcode` options persist for the active producer and are reused on agent rotation; `BuildOptions module=crystal_pack` persists them without rebuilding. `crystal_pack` also accepts `link_options`, which applies Crystal Palace BTF transforms to both PICOs.

### Source history

`--git` (default on) records every writable source root in a shadow repository under `<store>/git/<loop>/<root>/`. It uses the pure-Go go-git library, so no git binary, hooks, or user configuration is involved; the module's own checkout and the operator's repository are never modified. The loop commits the baseline, one commit per cycle before the build (source edits only; generated files and build outputs are excluded), and a final or partial commit when it stops. Commit messages name the cycle and mechanism, each cycle summary carries `git_commits`, and the final answer carries `git_heads` and `git_dir`.

`GitHistory` returns commit messages and changed-file stats to the workers. `--git=false` disables the record.

### Guest debugging

Guest SSH is available for both labs. The Windows debugger uses PowerShell and Defender exclusions in LitterBox; the Linux debugger uses bash commands and a staging directory in PenguinBox. Select the Linux path with `--module stager_linux`; the Linux lab entry supplies its SSH endpoint and key.

The debugger worker is enabled only when the operator supplies the sandbox guest's SSH endpoint and key:

```bash
detect_loop --guest-ssh litterbox@127.0.0.1:2222 \
  --guest-ssh-key ~/.ssh/litterbox-vm_ed25519
```

There is no implicit host. Without the CLI flags, the matching platform entry in `labs.json` supplies `guest_ssh` and `guest_ssh_key`; the legacy `EMP3R0R_DETECTION_GUEST_SSH` and `EMP3R0R_DETECTION_GUEST_SSH_KEY` variables remain a fallback for the CLI. Authentication is public-key only; password authentication and agent forwarding are never used. The host key is recorded on first use in `<store>/guest_known_hosts` and fails closed on a change; `--guest-ssh-fingerprint SHA256:...` pins it instead.

`--guest-ssh-exclude` sets the debug staging directory. On Windows it is also the Defender exclusion (default `C:\LitterBox\emp-debug`); on Linux it is created with `mkdir` (default `/tmp/emp3r0r-debug`). The coordinator prepares staging before every debugger session, and the debugger may also call `GuestSSH action=ensure_exclusion`. The debugger may change guest detection settings (Windows: Defender, firewall/ASR, RedEdr; Linux: analyzers and services) when they block execution or observation and records every change in `guest_actions`; such a cycle is debug-assisted, not a clean evasion baseline. The guest is the disposable sandbox: commands and file writes inside it are not restricted. The tool's only host-side credential is the configured SSH key; it exposes no other host paths and keeps no guest evidence on the host. The host boundary is the sandbox-only SSH key and host-key verification.

The debugger may launch a tool or artifact, kill a stuck process, read guest logs, collect a dump, and test C2 reachability from inside the guest. It cannot edit module source; when the cause is a crash or a rejected injection, it returns `source_fix_required=true` and a brief for the editor. A guest-side repair is confirmed by the host with a fresh `AgentStatus` poll, never by model text. The confirmation is recorded as `recovered_by=guest-debugger`; the cycle stays offline because the monitored run did not produce an attributable trace, so it is not a finding baseline.

### Managing loops

The operator console owns the detection loops it starts.

| Command | Purpose |
| --- | --- |
| `detect_loop list [--json]` | List running and on-disk loops with attempt, status (`running`, `stopping`, `stopped`, `verified`, `done`, `failed`, `interrupted`, `on-disk`), start time, pending prompts, resumability, and log path. Loops whose console exited appear from their on-disk state; older report-only loops are visible but not resumable. |
| `detect_loop resume <loop-id>` | Resume a stopped, interrupted, or failed loop from its on-disk manifest. The resumed attempt keeps the base loop and prior cycles, uses the saved options and source state, and starts a fresh attempt with the remaining cycle budget. Verified and done loops are listed but cannot be resumed; older report-only loops have no saved options and cannot be resumed. |
| `detect_loop stop <loop-id>` | Cancel the loop and wait up to five seconds for it to finish. Accepts the base ID or the current attempt ID. |
| `detect_loop stop --all` | Cancel every running loop. |
| `detect_loop prompt <loop-id> <instruction...>` | Append an instruction to the loop's prompt queue. The loop reads it before its next model session and includes it in the next `DetectionCycle` result. |
| `detect_loop start [options]` | Explicit launch form; `detect_loop [options]` remains the shorthand. |

The console cancels every loop when it exits. A module build already running finishes before the loop stops.

`detect_loop prompt` cannot interrupt an in-flight model turn or sandbox run. Use `detect_loop stop` to cancel the loop, or wait for the next cycle result.

Each loop writes its resolved options and current attempt to `<detection store>/loops/<base-loop-id>.json` in a 0700 directory with file mode 0600; a resumed loop keeps its log under `<detection store>`. `detect_loop ls` merges those manifests with the in-memory registry and with report-only loops. `detect_loop resume <loop-id>` reads the manifest and starts the next attempt with the saved source state, shellcode/producer settings, and remaining cycle budget; the source history, prior cycles, pending edits, and last executing payload are loaded from the loop database. Report-only loops created before manifests existed remain visible but are not resumable because their original options were not saved.

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
- when the debugger is enabled, use a sandbox-only SSH key: the debugger can change guest detection settings and run commands as needed to make the payload observable, the key is its only host-side file, and it is scoped to the LitterBox or PenguinBox guest, never a target;
- restrict egress to the model provider and the LitterBox sandbox;
- rebuild or discard the VM after a run instead of reusing a workstation;
- keep the model provider's data handling in mind: source excerpts, build logs,
  and sandbox telemetry leave the host.

The next step is to run the operator console in a disposable VM managed alongside
LitterBox, so a host-side build is no longer a trust boundary.

### Producers

For Windows, `--producer name` selects an installed shellcode producer module and `--producer name=dir` points at an uninstalled tree. The installed `donut` and `crystal_pack` modules are added automatically. For `stager_linux`, the shipped `malasada` module is always used; `--producer` is rejected and there is no producer path to configure. The model may read and edit a producer's source (`EditSource module=donut` or `module=malasada`), then call `BuildShellcode`. The `donut` module rebuilds its x86/x64 loader stubs and
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
- makes the artifact the shellcode for every later cycle;
- persists the producer's non-path options for the active producer, so an automatic agent rotation rebuilds the same wrapper instead of the module defaults.

`crystal_pack` declares `link_options`, a space-separated list of Crystal Palace BTF transforms (`+optimize`, `+disco`, `+gofirst`, `+mutate`, `+shatter`, `+blockparty`, `+regdance`, `+relax`, `+unwind`). `build.sh` copies both specs into a temporary tree and inserts the selected options before each export, so the inner PICO and the outer loader both receive the linker's transforms without editing `loader.spec` or `pico.spec`. The Makefile and `common.mk` compile flags are correctness fixes and are not an evasion surface.

`GenerateAgent` rebuilds the Go agent itself without wrapping it. It accepts
`agent_type=windows_executable` or `windows_dll` and `arch=amd64`; the C2
address always comes from the operator configuration. The result is the agent
EXE/DLL as `artifact_path`. Call
`BuildShellcode` with `producer=donut input=<artifact_path>`, or with
`producer=crystal_pack dll=<artifact_path>` for Crystal Palace PICO shellcode;
the producer output becomes active.

A producer edit and a producer swap are different mechanisms. `producer` edits
the current producer's source. `producer-swap` changes the wrapper itself and
requires `GenerateAgent agent_type=windows_dll` followed by `BuildShellcode
producer=crystal_pack dll=<artifact_path>`; the host rejects a `producer-swap`
cycle when the active producer did not change. `crystal_pack` output is
exercised by the Crystal-Kit module tests, including a deliberately invalid
PICO that the DLL loader's crash gate contains; a failed PICO build or load is
reported as a cycle error like any other producer failure. While
`crystal_pack` is the active producer, automatic agent rotation builds a
`windows_dll` agent even if `--agent-type` selected an executable, because
Crystal Palace PICO cannot wrap an EXE.

For `loader_windows`, the loop rejects a cycle whose artifact is too small to
contain the active shellcode, and rejects a dynamic cycle the sandbox never
executed. This prevents a loader that drops the agent payload just to reduce
detections.

`--read-root dir` adds a read-only source root (repeatable). By default the
loader's shared build inputs (`modules/common`, `c_agent/*/util`) are exposed
read-only, so the model can trace linked code without being able to edit it.

The Windows loop also exposes the editable Go agent tree as `go_agent`, next to
`c_agent`. Use `EditSource module=go_agent` for agent transport, syscall,
string, anti-debug, or memory behavior; `GenerateAgent` rebuilds from that
source with the selected feature tags.

If a cycle regresses, `RevertToPayload` replays the inverse of every recorded edit made after the chosen payload and restores the module and producer source, producer options, and build options. `DetectionCycle` records a mechanism label, one falsifiable prediction, the observed result, and the stage set with each cycle. It rejects a cycle when the design key (source, build options, producer options, producer, and agent type) is unchanged; fresh shellcode from TOFU rotation alone is not a change. A verified cycle with a missing analyzer is not comparable: it does not replace the finding baseline, and the report marks its coverage incomplete. Detection findings and static hygiene are counted separately: the regression gate treats a new detection or hygiene high as a hard regression, then compares real verdicts, then weighs medium findings and static hygiene so a material static win can outweigh a medium increase, and excludes build-random stringnalyzer and coverage/attribution context from top findings and comparison. The host refuses a third cycle on a mechanism whose last two cycles made no high-finding, static-finding, or verdict progress. `producer-swap` is a distinct mechanism: the host rejects it unless the active shellcode producer changed. The resume dossier carries the recent mechanism, prediction result, tested note, and edit reasons so a fresh agent session does not lose the direction it already tried. The cycle budget spans all attempts of one logical loop; it and the active shellcode are shown in the prompt and in every `DetectionCycle` result. `--iterations` and `--turns` default to 3 and 60; an explicit value is used as-is. `--stages` accepts `static`, `dynamic`, and `edr`; the loop requires at least one executing stage. `EditSource` has no separate per-cycle edit cap; a redesign may use as many edits as the turn budget allows.

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

`--inject` and `--process` seed the initial build options. The editor can change any declared loader build option at runtime with `BuildOptions`, and an empty value leaves the module's own default in control. `--iterations` defaults to 3; the role turn flags default to 24 for the planner and debugger and 60 for the editor. An explicit value is used as-is, and the cycle budget is shown in every worker brief and in every `DetectionCycle` result.

The loop writes one log file under `<workspace>/detection/` and opens a
separate tmux window tailing it; `emp3r0r.log` is untouched. When verification
is enabled, agent checks and rebuilds use the console's existing C2 connection
(`detect_loop` must therefore run from a connected operator console for live
verification). `AgentStatus`, `RunModule`, and `CleanupAgent` are only
registered when verification is configured. MCP `detection_loop` accepts an `agent_uuid` only when `generate` or
`generate_c` returned it in the same MCP session; it runs the same checks.
Without it the loop records `execution=unverified`. `GuestSSH` is registered when the CLI supplies `--guest-ssh` or the matching `labs.json` entry supplies `guest_ssh` and `guest_ssh_key`. MCP `detection_loop` does not accept guest SSH overrides; set `guest_ssh` and `guest_ssh_key` in the matching Windows or Linux entry of `labs.json`.
The sandbox is probed once, and a detection failure is not retried by the host: its error, build tail, stage errors, and trace identity are given to the model, which can inspect the source and telemetry and call `DetectionCycle` after a fix. A build failure is different: when an edit breaks the build and a verified baseline exists, the host restores the last executing source, shellcode, and build options, including source edits that never produced a payload, then allows up to two retries of the same plan with the restored tree. A build failure before any payload has checked in has no verified baseline to restore. A baseline failure therefore starts the model session instead of rebuilding the same payload again, and a failed attempt does not consume the cycle budget. Model-session failures, empty turns, and provider errors back off and continue the same session; after a bounded number of restarts the step is reported as an infrastructure failure, not as a failed hypothesis. A trace without a payload PEB is recorded and kept for the model with the `telemetry/attribution` finding instead of being detonated again. One build/detonate/verify cycle is bounded by `--cycle-timeout` (default 60m). A planner or editor session that completes no cycle within its decision window is continued with a forced answer, not restarted; the loop continues. A sandbox outage fails the cycle before any model session: a baseline outage returns immediately, and a mid-loop outage retries the same plan with bounded backoff. When the debugger identifies a source-level execution fault, a planner stop is converted into one editor cycle for that fix, bounded to two attempts. One model session is bounded by `--session-timeout` (default 2h), and a session with no tool call by `--tool-idle-timeout` (default 30m). An in-flight tool suspends the idle check and an in-flight cycle is bounded by its own deadline. `--timeout 0` (the default) means no loop-wide deadline. A final answer that is not the requested JSON object is stored as the summary with `parse_error` instead of ending the run. The loop writes the full Markdown report to `<workspace>/detection/reports/<loop>.md` and a compact executive summary to `<loop>-summary.md`, emits the full report through the tmux log pane when the loop finishes, and stores the report in `loop_results.report`. If the loop is stopped or fails before the final answer, it writes a partial report and summary from the cycles completed so far. The operator console prints the rendered executive summary, not the raw report.

Loop timestamps use local time. A `[progress]` heartbeat is written every two minutes with elapsed time, cycles used, tool calls, sessions, input/output and cache tokens, the estimated cost, the last terminal reason, last execution state, and the expected agent UUID, so a long model session is visibly alive. Cost is shown as `unconfigured` until the price flags are set. The final report and its executive summary lead with high findings, static signatures, total findings, and Defender verdicts, then map each baseline top finding to its final status and the first cycle/edit where it stopped appearing. Top findings are capped at eight per cycle, so absence from the final list is reported as "not in final top findings", not as proof of removal. Per-role token usage, the estimated cost, and the detailed edit log follow; the sandbox risk score is not the optimization target.

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
LitterBox result that nests `rededr.findings`. For Linux it accepts a
PenguinBox dynamic result, a Tracee JSONL stream, or Falco JSONL alerts; the
trace is tagged `platform=linux` and attributed to the guest process that
executed the payload.

`detection_telemetry_import` accepts `path` or `url` plus optional `module`,
`artifact`, `run_id`, and `source`. A `path` must be a regular file under the
detection store; symlinks and operator files elsewhere are rejected. A `url`
must use one of the configured lab origins, and redirects may not leave it;
save remote telemetry under the detection store and pass `path` instead. `detection_run` imports every saved sandbox result
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
- Ambient instrument images such as `RedEdrDll.dll`, `LitterBox\Scanners`, and MSVC runtimes are stored as `signal=noise`. The feedback view and the actionable-finding check skip them, so they cannot trigger another cycle. The payload's own `LitterBox\Uploads` path is the sample, not an analyzer, and is attributed normally.
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
the `findings` table. The loop treats a behavioral RedEdr finding (cross-process write/protect, thread suspend, remote thread, child process, or audited handle access) as actionable even when no literal source line matches; analyzer summaries still require a source match or a real verdict, and unmatched analyzer findings remain residuals. Analyzer status and errors are
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
the run records. The `traces` table carries a `platform` column (`windows` or
`linux`), and every cycle summary records the same field, so Windows and Linux
payloads share one database without mixing their evidence.
Feedback is derived from the stored run, so a run can be inspected without
detonating the payload again.
