## Background

This project is a Go codebase. Work from the module root (`core/` for the Go module). Read `README.md` and `TESTING.md` before making changes. Keep responses concise and finish tasks rather than stopping early. Do not attempt reading the whole codebase before starting your work; only focus on relevant files and start coding as early as possible; expand code scanning while you are coding and fix errors accordingly.

Try not to `grep` from `stdout` of a command. Always prefer writing logs to disk before `grep`.

## Code style

- Run `gofumpt -w` and `goimports -w` on every changed `.go` file before committing. `gofmt` alone is not sufficient: the project expects the stricter gofumpt formatting and goimports group/ordering.
- Verify the whole module still builds and the affected packages' tests pass after formatting.
- Wrap errors with context: `fmt.Errorf("do x: %w", err)`. Match the surrounding file's style.
- Do not introduce or keep `TestDummy`-style empty tests. Tests must assert real behavior; delete meaningless tests instead of faking coverage.
- Write comments explaining why (concurrency safety, invariants, ordering), not what.
- Keep code compiling on all supported platforms (`linux` and `windows`; operator/c2 run on `linux` only); platform-specific files use `//go:build` tags and must have working stubs for other platforms.

## Concurrency

- Use `sync.Map` for state shared across goroutines; never a plain map.
- Values stored in shared maps are immutable snapshots: copy, modify, publish. Never mutate a struct through a pointer obtained from a `sync.Map`.
- Never reassign a `sync.Map` variable that other goroutines may still use; clear with `Delete`/`Clear`.
- Do not hold a lock during network or disk I/O.
- Use `sync.Once` for one-time init and `sync/atomic` for shared counters/flags.
- Run `go test -race` on packages you change.

## Secure Communication

- TOFU should be enforced.
- All communication data needs to CBOR-encoded and encrypted properly with PFS key.
- Initial check-in phase is the only phase where static keys can be used. Sessions need to be re-keyed immediately after this phase.
- Reject early in new check-ins if anything doesn't work; avoid executing more work such as CBOR decoding.

## Logging and I/O

- Use the project's `lib/logging` package (`logging.Infof`, `Debugf`, `Warningf`, `Errorf`), never the stdlib `log`.
- Sanitize untrusted text before rendering or logging it; never print agent/remote-controlled bytes raw.
- Treat all remote input as hostile: validate lengths, indexes, and types; never panic on malformed input. Guard before indexing slices derived from input.
- Do not write files with predictable or brand-identifying names; prefer in-memory or opaque temporary storage (`memfs`).
- Use `crypto/rand` (or the project's crypto-backed helpers) for anything security-relevant; do not introduce `math/rand` for keys, nonces, or names.

## Compatibility

- No legacy/back-compat code: all binaries (agent, CC/operator, tools) must come from the same build batch. If wire format or a scheme changes, migrate everything in one change — do not keep old-path shims or "legacy" aliases.

## memfs

- Only scheme is `memfs://` (e.g. `memfs:///test.bin`); emit it, never `mem://` or any other alias.
- Flat map (`MemFileMap` under `MemFileLock`): no real dirs, just root `memfs:///`; path-like keys group by string prefix.
- No `mkdir` on memfs (fail with error, see `MkdirAgent`). `ls` lists the root or a key prefix; `rm` deletes a key or a whole prefix, cleaning its spill files; never delete the root.
- Over-budget writes spill AES-GCM-encrypted to unmarked `os.CreateTemp(dir, "")` files; keep disk I/O out of `MemFileLock`.
- Never persisted; agent advertises keys via mesh gossip for peer pulls.

## Module System

- Read `module_development_guide.md`.
- Read `./core/modules/`.
- Tools such as `./core/cmd/bofrunner/` should be used for standalone testing. Create new tools if needed.

## Testing

- Fast loop: `go test ./lib/...` plus the packages you touched. Full suite may be slow (network/integration tests).
- CI: `test.yml` defines how tests are run by GitHub Actions.
- When fixing a bug, add a regression test that fails on the old behavior first.
- Do not commit generated artifacts, compiled binaries, or scratch files.
- Update tests or add new ones as you make changes.
- Tests should not assume existing logic is correct. Focus on desired outcome of the functions and cover edge cases.
- When writing tests, invoke production code as much as possible. Do not create dummy cases so tests can pass but no real code is tested. Actively correct tests that don't comply with this principle.

## Deliverables

- Prefer small, focused commits with descriptive messages.
- Do not commit unless asked.
- Commits have to be signed. If your environment doesn't support signing, provide `git` commands so users can commit manually.
