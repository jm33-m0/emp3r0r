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
request touching `core/` against the `v5` branch.

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
- `c_agent` builds its unit tests and fallback fuzzers with `zig cc` and
  ASan/UBSan. `make coverage` is the exception: it uses GCC and `gcov`.
- `modules/stager_linux/test` builds and runs the Linux shellcode stager over
  raw and packed formats, all built-in download transports (including TCP and
  UDP), and the C agent delivery modes. It requires Linux and `CGO_ENABLED=1`.
  `make -C core/modules/stager_linux test` also runs the mask and LZSS decoder
  unit tests.
- `lib/memmod` and `lib/syscall/smw` need cgo on Windows, plus MSYS2 mingw and
  `nasm` to assemble the SilentMoonwalk stub.
- The `lib/driver` load/unload round trip only runs when
  `EMP3R0R_TEST_DRIVER_PATH` points at a signed `.sys` file. The rest of the
  package tests run normally.
- `internal/transport` ECH integration tests query real ECH-publishing domains
  (`crypto.cloudflare.com`, `tls-ech.dev`) through a public DoH resolver and
  perform a real ECH handshake with both the uTLS and crypto/tls clients. They
  need network egress; use `go test -short` to skip them offline.
- The Tor end-to-end tests in `modules/stager_linux/test` start a Tor hidden
  service and check in through the custom bridge with both a Go agent built
  with `with_transport_tor` and a C agent built with `TRANSPORT=tor`. They are
  opt-in because they need a Tor binary and Tor network access:

  ```bash
  EMP3R0R_TOR_INTEGRATION=1 TOR_BIN=/path/to/tor \
    go test -v -timeout 8m -run TestTorCustomC2EndToEnd ./transports/tor
  ```

  Set `TOR_LIBDIR` if Tor's libraries are not on the loader path, and
  `EMP3R0R_TOR_KEEP=1` to keep the temporary workspace.

## How CI runs it

`.github/workflows/test.yml` runs one job per OS (`ubuntu-latest`,
`windows-latest`) on Go 1.26:

- **Linux** runs `go test -v -race -coverprofile=coverage.txt -covermode=atomic
  ./...` with `EMP3R0R_RACE_ON=1`, installs zig 0.16.0, then runs the cgo BOF
  loader tests, the `internal/cc/modules` integration tests, and the stager
  lifecycle, packer, TCP/UDP, and C agent end-to-end tests.
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
