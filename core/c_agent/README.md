# emp3r0r C agent

The C agent is the Linux counterpart of emp3r0r's Go agent: one hosted binary,
PIC shared object, or raw PIC payload that speaks the same CBOR C2 protocol and
runs the same command surface. It builds with the project's pinned `zig`
toolchain and, by default, links no crypto or HTTP library at build time;
`libcrypto`/`libcurl` are resolved at runtime through `dynload`.

## Design

### Layers

```
c2_agent_config  ->  c2_transport  ->  c2_secureconn  ->  c2_messages
(bootstrap)          (http_poll)      (framing+crypto)    (CBOR)
```

- **Bootstrap.** The binary carries an encrypted CBOR `c2_agent_config`. The
  build-time `MagicString` decrypts it and derives the per-build PSK.
- **Transport.** `http_poll` simulates a bidirectional stream with
  init/read/write/close markers from the malleable profile. A duplex transport
  returns a connected stream directly.
- **SecureConn.** Every stream is framed and encrypted. The first frame on a
  new stream is a `MsgAuth` CBOR envelope.
- **Messages.** CBOR envelopes carry check-in, tunnel, job, and file data.

The wire format is normative in [PROTOCOL.md](./PROTOCOL.md); the C headers in
[`include/`](include/) are its machine-readable form.

### Providers

| Group     | Selector    | Providers                                           |
| --------- | ----------- | --------------------------------------------------- |
| Libc      | `LIBC`      | `glibc` (default), `musl`                           |
| Crypto    | `CRYPTO`    | `openssl` (runtime libcrypto), `mbedtls` (vendored) |
| Gzip      | `GZIP`      | `miniz` (vendored), `none`                          |
| Transport | `TRANSPORT` | `libcurl`, `http_raw`, `libssl`, `tor`, or `transport_<name>.c` |

Crypto, gzip, and transport providers are one file each in the matching `src/`
directory. A custom transport implements `c2_transport_create()` and
`c2_transport_name()`, reads `cfg->cc_address` and
`c2_agent_config_option(cfg, "key")`, and returns a raw `c2_stream`. The Tor
SOCKS5 provider in `src/transport/transport_tor.c` is the reference.

The hosted agent links libc dynamically; static libc is not supported because
`dynload` needs a dynamic loader and `/proc/self/maps`.

### Lifecycle

1. Decrypt the config, derive the PSK, generate or load the P-256 identity.
2. Check in on the checkin route; wait for `checkin-ok`.
3. Open the `msg` route, send a hello, run ECDH/HKDF, switch to the session key.
4. Poll for jobs for the configured window, reply with the same `JobID`, then
   close the tunnel and enter masked sleep.
5. `www` download and gzip'd `ftp` upload use dedicated streams.

### Stager cooperation

A C agent delivered by `core/modules/stager_linux` can be masked while it
sleeps. The stager publishes a mask entry point in its shared state block; the
agent calls it from its sleep cycle. The stub encrypts the agent's images,
heap, and stack with a fresh key and restores them on wake. The agent closes
the message tunnel before masking, so no network traffic happens while masked.

### In-memory module runners

Two dependency-backed runners execute module payloads in memory:

- **BOF** (`BOF=1`, default): a Linux relocatable object is mapped and run by
  the `coffloader_linux` dependency (`bof_run`), cached in memfs as
  `memfs:///coffloader_linux.so`. Console command: `bof`.
- **RV32IMA BOFs** (`RVVM=1`, default): an RV32 `ET_REL` BOF is interpreted
  by the `rvvm_linux` dependency (`rv_run`), cached in memfs as
  `memfs:///rvvm_linux.so`. The interpreter links libc dynamically for its
  host-call services; the BOF runtime is freestanding. There is no standalone
  `rv` command: an `rv` payload is always a BOF dispatched through
  `!custom_module`. See [`docs/rvvm.md`](../../docs/rvvm.md).

Both are reached by the C2's `!custom_module --type <coff|rv> ...` dispatch
and share `src/module.c` (invocation decoding) and `src/util/elfload.c`. Set
`BOF=0`/`RVVM=0` to compile either out.

### Output formats

`agent` is a hosted executable, `so` is a PIC `ET_DYN` shared object exporting
`main`, and `shellcode` is the shared object passed through malasada into raw
PIC. The shared object keeps a `PT_NOTE` for malasada's stage0 segment.

### Hardening

ELF images are mapped with `mmap` and relocated in memory. The loader guards constructors and IFUNC/IRELATIVE
resolvers with signal handlers, so a faulty image is rejected instead of taking
the agent down. Remote input is length-checked before use, and decoders never
panic on malformed CBOR or frames.

## Build

```sh
make -C core/c_agent lib             # hosted static library
make -C core/c_agent agent           # hosted reference executable
make -C core/c_agent so              # PIC shared object
make -C core/c_agent test            # unit tests (ASan/UBSan)
make -C core/c_agent fuzz            # fuzz targets (ASan/UBSan)
make -C core/c_agent coverage        # gcov coverage
```

`ARCH` selects `amd64`, `386`, `arm`, `arm64`, or `riscv64`; `riscv64`
requires `LIBC=musl`. `GLIBC_VERSION` and `DYNLOAD_MODE` tune the glibc build.

```sh
make -C core/c_agent agent ARCH=arm64 LIBC=musl
make -C core/c_agent agent CRYPTO=mbedtls GZIP=none TRANSPORT=http_raw
make -C core/c_agent agent BOF=0 RVVM=0
```

### Config embedding

The operator renders the encrypted CBOR config into a C translation unit and
passes it as `CONFIG_SRC`:

```sh
make -C core/c_agent agent CONFIG_SRC=/path/to/config_embedded.c
```

Without `CONFIG_SRC` the agent links with empty defaults and exits at startup.
From the operator console, `generate_c` does this automatically:

```text
generate_c --type glibc --arch amd64 --cc your.domain.com
generate_c --type musl --arch arm64 --cc your.domain.com \
  --crypto mbedtls --gzip miniz --transport http_raw

# Custom Tor transport (bridge on the C2 host)
generate_c --cc abcdefghijklmnop.onion:80 \
  --c2-channel-mode tor --allow-custom-transport \
  --transport tor --transport-option socks5=127.0.0.1:9050
```

### clangd

clangd reads `compile_flags.txt` for the agent's default flags and include
paths, so no generated compilation database or external tool is required.
`.clangd` disables unused-include cleanup, and `.clang-format` keeps the tree in
the project style. The stager and Linux modules have their own
`compile_flags.txt`.

## Test

`make test` runs the unit tests under ASan/UBSan. `make fuzz` runs the
mutational fallback; with clang installed, use libFuzzer:

```sh
make -C core/c_agent fuzz FUZZER=libfuzzer HOSTCC=clang FUZZ_TIME=60
```

Corpus entries persist under `build/corpus/<target>/`, and crashes are written
to `build/crash/`.

## Protocol

The normative wire format, constants, message schemas, check-in flow, PFS key
exchange, conformance vectors, and minimal-agent checklist are in
[PROTOCOL.md](./PROTOCOL.md).
