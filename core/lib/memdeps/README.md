# memdeps

Scoped lifetime management for in-memory DLL/SO **dependency** modules.

`memmod` knows how to map an image; `memdeps` decides how long it stays mapped.
Its single rule is: **map on use, unmap on return.** A dependency therefore
never stays resident in cleartext once the code that needed it has finished.

The raw image is never held here — it lives encrypted in memfs and is re-fetched
on demand through the resolver the agent wires at startup
(`memdeps.SetResolver(fetchDependency)` in `core/internal/agent/modules/mod.go`).

## API

```go
// Resolve a named dependency, map it, run fn, unmap it.
func Use(name string, fn func(*memmod.Module) error) error

// Map caller-supplied bytes, run fn, unmap.
func Run(data []byte, fn func(*memmod.Module) error) error
```

Both wrap the callback with `defer module.Free()`, so the mapping is released on
success, on error, and on panic. The `*memmod.Module` handed to `fn` is valid
only inside the callback and must not escape.

## Consumers

| Consumer | How it uses memdeps |
| --- | --- |
| Windows COFF/BOF loader | `coffloader.RunCOFFDependency` → `Use("coffloader", …)` |
| `dll` module payloads | `coffloader.RunWindowsCOFFViaDLL` → `Run(dllData, …)` |
| Linux eBPF builtins | `libbpf.WithLibrary` → `Use("libbpf", …)` |

Scripts that call `mem_load_library` directly are covered separately: their
handles live in a per-run registry and `script.Run` calls `releaseRunModules`
before returning, so nothing outlives the run.

## Tests

`memdeps_linux_test.go` builds a minimal `.so` with zig (skipped when zig is
absent or the race detector is on) and asserts that the mapping exists inside
`Run`/`Use` and is gone once they return — including when the callback returns
an error.
