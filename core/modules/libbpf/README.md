# libbpf

Builds the self-contained `libbpf.so` dependency used by the Go loader
`core/lib/libbpf` and the `ebpf_*` Starlark builtins. It is a library, not a
runnable module: another module declares it in `dependencies`, the C2 builds
and hosts `libbpf.<arch>.gz`, and the agent maps it in memory on first use.

`libbpf.so` is statically linked against libelf and zlib, so it depends only on
libc and is loaded by the **shared-object agent** (`stub-<arch>.so`).

## Build

Self-contained and reproducible. `make` (invoked by the C2 through
`build.sh`) compiles everything with the zig toolchain that ships with
emp3r0r:

1. downloads zlib and elfutils (`libelf`) at pinned versions and verifies their
   SHA-256 sums;
2. builds zlib and a PIC, TLS-free `libelf` with zig;
3. clones libbpf at a pinned commit and builds `libbpf.so` against them;
4. strips the shipped object (`-Wl,--strip-all`): `.dynsym` is kept because
   the in-memory loader resolves imports through it, while `.symtab` and any
   debug sections are dropped.

`ZIG_TARGET` selects the target (default `x86_64-linux-gnu.2.17`, i.e. the
same glibc baseline as the builder image). Override it to cross-build for
another agent arch, keeping the suffix, e.g. `ZIG_TARGET=aarch64-linux-gnu.2.17`.
Do not drop the `.2.17`: zig's unversioned GNU targets default to a much newer
glibc and the resulting `libbpf.so` will fail to load on older targets.
Artifacts are cached under `.build/`; a second invocation is a no-op.

Requires `zig`, `git`, `curl`, `make`, `tar`/`bzip2` and `sha256sum`.

## Use from a module

```json
"dependencies": ["libbpf"]
```

```python
progs = ebpf_progs()   # [{id, type, name, load_time}, ...]
links = ebpf_links()   # [{id, type, prog_id}, ...]
maps  = ebpf_maps()    # [{id, type, name, key_size, value_size, max_entries}, ...]
ebpf_detach(links[0]["id"])
```

Enumeration needs `CAP_BPF`/`CAP_SYS_ADMIN`; without it the lists are empty.
The Go package (`core/lib/libbpf`) also exposes `Load`, `OpenMem`, `Object`,
`Program` and `Link` for callers that want to load and attach an object.
