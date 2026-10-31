# Agent Instructions

## Environment

- On Windows, use WSL. Build and test in the `emp3r0r-builder` container from
  `Dockerfile`; install podman and build the image if it is missing. Use the
  container for all work unless you must test a Windows build. Sync files to
  WSL's native filesystem before testing.
- The Go module root is `core/`. Read `README.md` and `docs/TESTING.md` before
  changing code.
- Do not read the whole codebase first. Find the relevant files, start coding,
  and expand only as needed.
- Do not filter live or long-running command output through `grep`, `head`, or
  `tail`. Redirect complete stdout and stderr to a log file, then inspect it.
  Keep stderr and the exit code.
- Do not use `install.py` or `build.py` for tests. They build release tarballs
  and are slow.

## Build

- Use the pinned zig toolchain for all C builds: `zig cc`, `zig c++`,
  `zig ar`, and `zig ranlib`. Keep `REQUIRED_ZIG_VERSION` in `core/build.py`
  in sync with `Dockerfile` and `.github/workflows/test.yml`.
- Keep the nasm installed by `core/build.py` available for SilentMoonwalk
  stubs in `loader_windows` and Crystal-Kit.
- Build agent payloads that link C with zig. `core/build.py` sets
  `CC="zig cc -target ..."`:
  - Linux cgo stubs (amd64, 386, arm64, riscv64): `*-linux-musl`, static.
  - Linux shared objects: `*-linux-gnu.2.17`; riscv64 uses `*-linux-musl`.
  - Windows shared objects: `*-windows-gnu`.
  - Pure-Go stubs and C2 binaries need no C compiler. The builder image maps
    mingw-w64 compiler names to zig.
- Build C modules with zig too: Linux stager, `libbpf`, `hello_linux`, and the
  Windows loader.
- Build freestanding position-independent stages with `-nostdlib` and no libc
  target.
- Link hosted artifacts (Linux `SO`/`EXE` stagers, the agent `c-shared` object)
  against glibc dynamically, never statically. Pin the oldest ABI:
  `*-linux-gnu.2.17` for `__libc_dlopen_mode`, `*-linux-gnu.2.34` for
  `dlopen`/`dlsym`/`dlclose`. Use the per-arch targets in `core/build.py`.

## Code Style

- Run `gofumpt -w` and `goimports -w` on every changed `.go` file.
- Run `clang-format -i` on every changed C source and header file.
- Build the module and run the affected packages' tests after formatting.
- Reuse code. Do not hardcode values or duplicate logic.
- Wrap errors with context: `fmt.Errorf("do x: %w", err)`.
- Write comments that explain why, not what.
- Never address the user, answer the prompt, or justify rule compliance in
  code, comments, or documentation. Do not mention rejected alternatives or
  absent mechanisms just because a prompt or rule forbade them; describe only
  what the code actually does.
- Do not add empty tests. Tests must assert real behavior.
- Keep code building on Linux and Windows; operator and C2 code is Linux-only.
  Put platform code behind `//go:build` tags and provide stubs.

## Concurrency

- Use `sync.Map` for state shared across goroutines, never a plain map.
- Store immutable snapshots in shared maps: copy, modify, publish. Do not
  mutate a struct through a pointer read from a `sync.Map`.
- Do not reassign a `sync.Map`; clear it with `Delete` or `Clear`.
- Do not hold a lock during network or disk I/O.
- Use `sync.Once` for one-time init and `sync/atomic` for shared counters and
  flags.
- Run `go test -race` on changed packages.

## Transport Security

- Enforce TOFU.
- Encode all communication with CBOR and encrypt it with the PFS key.
- Use static keys only for the initial check-in, then re-key the session.
- Reject invalid new check-ins before running more work such as CBOR decoding.

## Operator Isolation

- Treat the server as the trust root. Enforce every boundary on the server,
  never in the operator client. See `docs/SECURITY.md`.
- Derive operator identity from the authenticated WireGuard peer address
  (`operatorIDFromRemote`). Trust the `operator_session` header only from
  loopback.
- Call `requireOperatorIdentity` on every operator-facing endpoint and return
  401 for unidentified callers.
- Use `acquireAgentLock` for single-owner agent claims. Return 409 for a second
  claim or a command from a non-owner. Refuse `forget_agent` while another
  operator owns the agent. Release locks on target switch, disconnect, and idle
  timeout.
- Keep job ownership immutable with `setJobOwner` (`LoadOrStore`).
- Owner-check SOCKS5 pivots, FTP streams, and WWW relays, and list only the
  caller's entries. Route agent-initiated work to the agent's owner with
  `agentLockOwnerSession`; fall back to the sole online operator only in
  single-operator mode.
- Let only the server change the operator idle timeout in multi-operator mode
  and refuse operator updates.
- Let `sign_agent` sign only a validated UUID, never arbitrary content.
- Bind SOCKS5 pivots only to loopback or the C2 WireGuard address.
- Bound operator input and maps: request bodies (1 MiB), message-tunnel frames
  (4 MiB), and per-operator FTP streams and SOCKS5 pivots. Cap and sweep
  per-agent rate-limiter and replay caches.
- Audit every operator action, including denials, with `auditOperatorAction`
  in `~/.emp3r0r/operator_audit.log` (0600).

## Agent Identity and tmux

- Derive the operator-facing tag from the verified UUID with
  `util.GenAgentTag`; overwrite any agent-reported tag.
- Target agents by tag. Show the UUID for reference only. Make
  `forget_agent <tag>` resolve offline agents, and name the tag in rejection
  notices.
- Log both identifiers with `util.AgentRef(uuid)`.
- Pass only `util.IsAgentID`-validated identifiers to tmux. Sanitize agent
  fields before rendering; never send tmux format syntax such as `#{...}` or
  `#(...)` to a tmux command.

## Logging and I/O

- Use `lib/logging` (`Infof`, `Debugf`, `Warningf`, `Errorf`), never the stdlib
  `log`.
- Keep release builds free of logging. In C, guard logging with `DEBUG` and
  minimize string literals.
- Sanitize untrusted text before logging or rendering it.
- Validate lengths, indexes, and types from remote input. Never panic on
  malformed input and guard before indexing.
- Do not write files with predictable or brand-identifying names. Prefer
  in-memory storage or `memfs`.
- Use `crypto/rand` or the project's crypto helpers for keys, nonces, and
  names, never `math/rand`.
- Use `WriteFileAgent` and `memfs` for agent-side file I/O. Do not write files
  outside `memfs` except its disk spillage. Do not spawn subprocesses on the
  agent unless explicitly allowed.

## In-Memory Code Loading

- Never use `memfd_create` or `/proc/self/fd/N` plus `dlopen` to load code. A
  memfd is a named kernel object and a detection signal.
- Map the image anonymously and apply its relocations yourself, as the Go agent
  does in `lib/memmod` and `lib/memdeps`. In C, use `src/util/elfload.c`.
- Use `dlopen` and `dlsym` only for libraries already present on the host, not
  for an image held in memory.
- Do not link or load `libdl.so.2` just to use `dlopen`/`dlsym`/`dlclose`. On
  glibc < 2.34, `libc.so.6` already exports the internal helpers
  `__libc_dlopen_mode`, `__libc_dlsym`, and `__libc_dlclose`; on glibc >= 2.34,
  `dlopen`, `dlsym`, and `dlclose` are in `libc.so.6` directly. Resolve them
  from `libc.so.6` (as `dynload` does) without loading `libdl`.

## Artifact Strings

- Treat every shipped artifact (agent, shellcode, stager, loader, BOF, DLL, and
  service executable) as inspectable by strings, exports, and symbol tables.
- Do not embed project names, module or tool names, technique names, or author
  handles. This includes service, mutex, event, pipe, and environment-variable
  names.
- Do not use a branded fallback name. Derive names from the host binary or
  module path, build-time input, or `crypto/rand`; fail if none is available.
- Keep exported symbols generic, such as `Run`, or resolve by ordinal.
- Keep project names out of debug-only strings too. Build scripts, module
  metadata, and C2 log text may describe the module; shipped artifacts must
  not.

## Compatibility

- Do not keep legacy or back-compat paths. Build every binary from the same
  batch. If a wire format or scheme changes, migrate every producer and
  consumer in one change.

## memfs

- Use only the `memfs://` scheme, for example `memfs:///test.bin`.
- Treat it as a flat map under `MemFileLock`. Use `memfs:///` as the root and
  string prefixes as groups.
- Do not create directories; `MkdirAgent` must fail. `ls` lists the root or a
  key prefix. `rm` deletes a key or prefix and its spill files, never the root.
- Spill over-budget writes as AES-GCM-encrypted `os.CreateTemp(dir, "")` files.
  Keep disk I/O out of `MemFileLock`.
- Never persist memfs. Advertise keys through mesh gossip for peer pulls.

## Modules

- Read `docs/module_development_guide.md` before adding or changing a module.
- Inspect `core/modules/` for an existing module to extend.
- Use standalone tools such as `core/cmd/bofrunner/` for testing, and add a new
  tool when needed.

## Documentation

- Write only user-facing or developer-facing technical reference. Never put
  conversational notes, prompt responses, or rule-compliance disclaimers into
  documentation.
- Put project guides in `docs/`. Keep the root `README.md`, `AGENTS.md`,
  `CHANGELOG.md`, and `LICENSE` at the repository root.
- Keep each component's or module's `README.md` in its directory. If it has a
  guide in `docs/`, the README only links to that guide.
- Write user-facing docs in `docs/` for usage only: prerequisites, commands,
  options, output, and constraints. Leave internals out.
- Add a `docs/<name>.md` page for a tool or module that operators configure or
  run directly. Do not duplicate a docs page in a README.
- Keep links relative and valid. Update every reference when moving, renaming,
  or adding a doc.

## Testing

- Run `go test ./lib/...` plus the packages you changed. The full suite is
  slower and includes network and integration tests.
- Follow `.github/workflows/test.yml` for CI behavior.
- When fixing a bug, add a regression test that fails before the fix.
- Update tests when behavior changes and add tests for new behavior.
- Exercise production code. Do not add dummy cases that only make tests pass.
- Do not commit generated artifacts, compiled binaries, or scratch files.

## Deliverables

- Report what you changed.
- List assumptions and their reasons.
- Prefer small, focused commits with descriptive messages.
- Do not commit unless asked.
- Sign commits. If signing is unavailable, provide the `git` commands for the
  user to run.
