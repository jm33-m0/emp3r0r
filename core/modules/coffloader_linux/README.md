# `coffloader_linux`

A Linux **Beacon Object File** loader, the Linux counterpart of the Windows
`coffloader` module. It is a dependency module (`agent_config.type = "so"`):
nothing invokes it directly, it is hosted by the C2 as
`coffloader_linux.<arch>.gz` and mapped by the C agent on demand.

## Source layout

- `loader_linux.c` — ELF object mapping, relocations, signal handling and the
  exported `Run`/`Free`/`LastError` ABI.
- `beacon_compat.c` / `beacon_compat.h` — the Beacon API shims BOFs resolve
  against, plus the captured output buffer.

## What it does

A Linux BOF module depends on it. The dependency is injected automatically from
`platform: "Linux"`, and a manifest may also declare it explicitly next to any
other dependency (it is not duplicated):

```json
"dependencies": ["coffloader_linux"]
```

The C2 hosts it as `coffloader_linux.<arch>.gz`; the agent maps it on demand.
Linux BOFs need libc symbol resolution, so they require a dynamically linked
Linux agent with libc mapped. A statically linked agent returns a clear
`statically linked` error instead of trying to map the loader.

`loader_linux.c` is the canonical loader, mapped by both agents as the
`coffloader_linux` dependency (the Go agent through `core/lib/coffloader`
and `memmod`, the C agent through `core/c_agent/src/util/elfload.c`):

- Parses an x86_64 `ET_REL` object.
- Packs `SHF_ALLOC` sections into one anonymous mapping with three page-aligned
  segments by protection (RX, R, RW), keeping the trampoline page inside the
  executable segment. Sections that are both writable and executable are
  rejected, so the image never contains an RWX mapping.
- Applies the `R_X86_64_64/32/32S/PC32/PLT32` relocations.
- Resolves undefined symbols to the mocked Beacon API first, then to the loaded
  `libc`, `libm` and `libgcc_s`, building a 16-byte `movabs/jmp` trampoline for
  each. The lookup reads those modules' dynamic symbol tables (the same policy
  `core/c_agent/src/util/elfload.c` applies to the loader's own imports), checks
  the symbol type and invokes a GNU IFUNC's resolver, so `memcpy`, `memset`,
  `strlen`, `strchr`, `strrchr` and `memcmp` resolve to the implementation
  instead of the resolver. `libdl` is never loaded. `getEnviron` and `getOSName`
  from the TrustedSec compatibility layer are mocked too.
- Applies `W^X` per segment and executes the requested entry point.
- Catches `SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE` during execution and returns an
  error instead of killing the agent.
- Rejects images larger than 64 MiB and truncates captured output at 8 MiB.

`Run` is the public entry point. `SetHostBridge` is the only other exported
symbol; every other symbol is built with `-fvisibility=hidden`.

The parser validates every offset and length against the object size before it
reads: the section-header table, each section payload, the symtab/strtab, each
relocation's target section and the resolved symbol's section/name. Malformed
input is rejected with an error, never a crash.

## Beacon API

The loader implements the Beacon compatibility API that BOFs commonly use:
`BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, `BeaconDataInt`,
`BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`, the
`BeaconFormat*` family, `BeaconIsAdmin`, `swap_endianess`, `getEnviron` and
`getOSName`. Their output is returned to the caller through `char **out`.

### Host primitives

An agent can install storage, session and relay primitives with
`SetHostBridge(ctx, read, write, upload, sha256, relay, exec)`. BOFs resolve the
wrappers below through the same symbol table:

```c
int ReadFile(const char *path, unsigned char **out, unsigned long *len,
             char *err, int err_cap);
int WriteFile(const char *path, const unsigned char *data, unsigned long len,
              char *err, int err_cap);
int UploadFile(const char *token, const char *path, unsigned long offset,
               char *err, int err_cap);
int Sha256Hex(const unsigned char *data, unsigned long len, char *hex,
              unsigned long hex_cap, char *err, int err_cap);
int RelaySocket(const char *token, int fd, int idle_seconds, char *err,
                int err_cap);
int ExecCmd(const char *cmd, int shell, char *out, int out_cap, char *err,
            int err_cap);
```

Each returns `0` on success and a negative status otherwise. Without installed
callbacks they return `-9` (unsupported). `UploadFile` streams the named file
through the registered FTP route from `offset`, so a BOF sends a file without
holding it in memory; downloads are not a BOF concern, because `put` is an agent
command. `RelaySocket` takes an already-connected socket and pumps it through the
C2 stream named by `token`, which lets a BOF own its own address resolution and
dialing while the transfer runs on agent threads. `ExecCmd` runs the command line in a child process and returns the byte count
copied into `out` (combined stdout and stderr), or a negative status; `shell`
selects `/bin/sh -c` or a direct exec of the tokenized command line.

## Arguments

`core/c_agent/src/bof.c` packs arguments in the Windows COFFLoader wire
format before calling `Run`: a leading `uint32` body length, then per
argument `int32`, `int16`, a length-prefixed **NUL-terminated** `char *`
(`z`/`cstr`/`S`), a length-prefixed NUL-terminated UTF-16LE `wchar_t *`
(`Z`/`wstr`), or a length-prefixed binary blob (`b`).

## Build

```sh
make -C core/modules/coffloader_linux
```

Built with `zig cc -target x86_64-linux-gnu.2.17 -shared -fPIC -O2` with
`-fvisibility=hidden`; the linker drops unused sections, emits no build ID, and
the `.comment` section is stripped. The output is `coffloader_linux.so`.

## Use

The C agent fetches `coffloader_linux.<arch>.gz` into `memfs:///` on the first
`bof` command and maps it in memory with `elfload` for the duration of one BOF
run:

```text
bof <object> [export] [args...]
```

where `<object>` is a path to a BOF already present in memfs (for example via
`download`) and `[export]` defaults to `go`.
