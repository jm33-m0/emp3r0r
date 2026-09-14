# Testing emp3r0r

The Go module lives in `core/`. Run the commands below from there.

## Running tests

```bash
cd core

go test ./...                                  # whole module
go test ./lib/crypto/...                       # one package tree
go test -v -run TestParseCmd ./lib/util/...    # one test
go test -v -run 'TestParseCmd.*' ./lib/util/... # tests matching a pattern

go test -coverprofile=coverage.out ./...       # coverage
go tool cover -func=coverage.out               # summary
go tool cover -html=coverage.out               # browser report

go test -race ./...                            # race detector
```

Plain `go test ./...` should stay green. CI runs on every push and pull
request touching `core/` against the `v4` branch.

### The `EMP3R0R_RACE_ON` switch

A handful of integration tests exercise real processes, full-stack pivots, or
in-memory PE mapping and are unreliable under the race detector. Those tests
skip themselves when `EMP3R0R_RACE_ON=1`, which is what CI sets for its race
run:

```bash
EMP3R0R_RACE_ON=1 go test -race ./...
```

Leave the variable unset (or set it to `0`) to include them when you are not
running with `-race`.

### Compiler- and platform-dependent tests

Some packages compile C or load real object files and need extra tooling:

- `lib/coffloader` builds a BOF at test time. `TestZigCompiledBOF` uses
  [zig](https://ziglang.org/download) as `zig cc` and skips when zig is not on
  `PATH`.
- `modules/stager_linux/test` builds and runs the Linux shellcode stager. It
  requires Linux and `CGO_ENABLED=1`.
- `lib/memmod` and `lib/syscall/smw` need cgo on Windows, plus MSYS2 mingw and
  `nasm` to assemble the SilentMoonwalk stub.
- The `lib/driver` load/unload round trip only runs when
  `EMP3R0R_TEST_DRIVER_PATH` points at a signed `.sys` file. The rest of the
  package tests run normally.

## How CI runs it

`.github/workflows/test.yml` runs one job per OS (`ubuntu-latest`,
`windows-latest`) on Go 1.26:

- **Linux** runs `go test -v -race -coverprofile=coverage.txt -covermode=atomic
  ./...` with `EMP3R0R_RACE_ON=1`, installs zig 0.16.0, then runs the cgo BOF
  loader tests, the `internal/cc/modules` integration tests, and the stager
  lifecycle test.
- **Windows** sets up MSYS2 with mingw-w64 and `nasm`, assembles the
  SilentMoonwalk object, runs `go test -v -race ./...` with cgo, then runs the
  BOF/module integration tests with `-gcflags=all=-d=checkptr=0` and
  `EMP3R0R_RACE_ON=0`.
- Linux coverage is uploaded to Codecov.

## Writing tests

- Name files `<file>_test.go` and keep them in the package under test. Use an
  external `_test` package only to break an import cycle.
- Prefer table-driven tests with `t.Run` subtests and descriptive names.
- Keep tests independent and clean up with `t.Cleanup` and `defer`.
- Test error paths and malformed input, not just the happy path. Network and
  parser input is hostile by definition; make sure it cannot panic or read out
  of bounds.
- Mark helpers with `t.Helper()` so failures point at the caller.
- Platform-specific tests need a build tag:

  ```go
  //go:build linux && cgo

  package shellcode_stager
  ```

- Security-sensitive code (crypto, parsers, memfs) should have known-answer
  vectors and boundary cases.
- Add a regression test that fails on the old behavior before fixing a bug.
- Do not add a test that can only pass. If it cannot fail, it is not a test.
