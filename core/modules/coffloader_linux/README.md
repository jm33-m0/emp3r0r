# `coffloader_linux`

A Linux **Beacon Object File** loader, the Linux counterpart of the Windows
`coffloader` module. It is a dependency module (`agent_config.type = "so"`):
nothing invokes it directly, it is hosted by the C2 as
`coffloader_linux.<arch>.gz` and mapped by the C agent on demand.

## What it does

A Linux BOF module depends on it. The dependency is injected automatically from
`platform: "Linux"`, and a manifest may also declare it explicitly next to any
other dependency (it is not duplicated):

```json
"dependencies": ["coffloader_linux"]
```

The C2 hosts it as `coffloader_linux.<arch>.gz`; the agent maps it on demand.

`loader_linux.c` is the canonical loader, mapped by both agents as the
`coffloader_linux` dependency (the Go agent through `core/lib/coffloader`
and `memmod`, the C agent through `core/c_agent/src/util/elfload.c`):

- Parses an x86_64 `ET_REL` object.
- Maps `SHF_ALLOC` sections into one anonymous, page-aligned region and applies
  the `R_X86_64_64/32/32S/PC32/PLT32` relocations.
- Resolves undefined symbols to the mocked Beacon API first, then to the host
  process (`dlsym(RTLD_DEFAULT, …)`), building a 16-byte `movabs/jmp` trampoline
  for each.
- Applies `W^X` per section and executes the requested entry point.
- Catches `SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE` during execution and returns an
  error instead of killing the agent.

`bof_run` is the only exported symbol. Everything else is built with
`-fvisibility=hidden`.

The parser validates every offset and length against the object size before it
reads: the section-header table, each section payload, the symtab/strtab, each
relocation's target section and the resolved symbol's section/name. Malformed
input is rejected with an error, never a crash.

## Beacon API

The loader mocks the subset of the Beacon API that BOFs commonly use:
`BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, `BeaconDataInt`,
`BeaconDataShort`, `BeaconDataLength` and `BeaconDataExtract`. Their output is
returned to the caller through `char **out`.

## Arguments

`core/c_agent/src/bof.c` packs arguments in the Windows COFFLoader wire
format before calling `bof_run`: a leading `uint32` body length, then per
argument `int32`, `int16`, a length-prefixed **NUL-terminated** `char *`
(`z`/`cstr`/`S`), a length-prefixed NUL-terminated UTF-16LE `wchar_t *`
(`Z`/`wstr`), or a length-prefixed binary blob (`b`).

## Build

```sh
make -C core/modules/coffloader_linux
```

Built with `zig cc -target x86_64-linux-gnu.2.17 -shared -fPIC -O2 -ldl`; the
`.comment` section is stripped. The output is `coffloader_linux.so`.

## Use

The C agent fetches `coffloader_linux.<arch>.gz` into `memfs:///` on the first
`bof` command and maps it in memory with `elfload` for the duration of one BOF
run:

```text
bof <object> [export] [args...]
```

where `<object>` is a path to a BOF already present in memfs (for example via
`download`) and `[export]` defaults to `go`.
