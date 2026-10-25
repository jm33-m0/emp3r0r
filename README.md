<img align="left" width="150" height="150" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

### emp3r0r

A C2 framework for Linux and Windows. Agents run in memory, keep working when links break, and can be extended with scripts.

<br clear="all" />

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/jm33-m0/emp3r0r?filename=core%2Fgo.mod)
[![Tests](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml)
![GitHub License](https://img.shields.io/github/license/jm33-m0/emp3r0r)
[![GitHub release](https://img.shields.io/github/release/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/releases)

<img width="1925" height="1147" alt="emp3r0r-readme" src="https://github.com/user-attachments/assets/945aef28-1c07-4701-a6d9-b8029ad8251e" />

## What is emp3r0r?

emp3r0r started as a Linux post-exploitation framework with interactive remote shells and autonomous network pivoting. Over time it grew into a multi-operator C2 with modular agents, a P2P mesh, and in-memory execution on both Linux and Windows.

## Features

### Scriptable agents

Every agent has an embedded Starlark engine. A module can add post-exploitation logic without rebuilding the agent or uploading an interpreter. Scripts run inside the agent process and use built-in APIs for file I/O, HTTP, process execution, and other common work. They can also call Win32 functions and Linux syscalls through the agent's API proxy. When a script needs an API that is not already present, it can load a DLL or SO from encrypted memfs or the C2 with [`mem_load_library`](#in-memory-library-loader), call its exports, and unload it when done. [Linux eBPF modules](#linux-modules-and-ebpf) use the same path to load `libbpf`.

Modules are a Starlark file and a small JSON manifest. The agent loads them in memory and does not spawn Python, Bash, PowerShell, or another command interpreter.

### Agent identity

The first successful check-in pins the agent's public key and signed UUID. Later check-ins must use the same identity. A different key or signature is rejected instead of quietly replacing the old agent. Removing an agent is an operator decision.

C2 and peer connections use ephemeral ECDH keys for each session. A compromised long-term key cannot decrypt traffic from earlier sessions.

### P2P mesh

Agents can discover each other and relay traffic through a gossip mesh. Peer links use camouflage mTLS 1.3, Windows SMB named pipes, or KCP over UDP, and every hop is encrypted. If a relay dies or the C2 becomes unreachable, traffic can move through another peer.

Files can also move directly between peers. The agent keeps fetched files in encrypted memfs and serves them to peers on request. If no peer has a file, the agent fetches it from the C2.

### Listeners and stagers

The C2 supports HTTP, TCP, and UDP listeners. The HTTP transport has configurable request profiles. The Linux stager is small, talks to the kernel through direct syscalls, and needs no libc on the target. Stager transports and packers are pluggable, so initial access can use whichever channel the target allows.

Stages and agents avoid RWX mappings. Code is mapped with the permissions it actually needs.

### BOF, ELF, and PICO modules

Compiled C modules run in the agent process on both platforms:

- Windows COFF/BOF objects with typed argument packing.
- Linux ELF relocatable objects loaded from memory.
- Crystal-Kit PICO modules with SilentMoonwalk call stack spoofing.

The repository ships Kerbeus-BOF, Remote-OPs, and a Situational Awareness suite. Running a BOF does not start another process or write the object to disk.

### In-memory library loader

`memmod` maps shared libraries into the agent's address space and calls their exports in place. On Windows it loads PE DLLs. On Linux it loads ELF `.so` files and applies relocations, imports, and symbol lookups without `LoadLibrary` or `dlopen`.

The PE side follows WireGuard's `memmod`. The ELF side follows [Sliver](https://github.com/BishopFox/sliver) and [sliverarmory/reflektor](https://github.com/sliverarmory/reflektor). `memdeps` sits on top: a module declares a dependency, the agent gets it from encrypted memfs or the C2, maps it for one operation, then unmaps it.

[Starlark modules](#scriptable-agents) can use the same loader directly with `mem_load_library`. They are not limited to APIs that are already loaded in the agent or target process.

### Linux modules and eBPF

Linux modules are Starlark scripts with access to the kernel through libbpf. The agent maps `libbpf` when a module needs it and exposes its API as Go-backed builtins. This uses the same on-demand loader that [`mem_load_library`](#in-memory-library-loader) exposes; libbpf is just another shared object the module asks for. A script can enumerate BPF objects, attach programs, manage maps and links, and start or stop uprobes.

[`ssh_harvest`](./core/modules/ssh_harvest/) is the worked example. It finds a pattern in `sshd`, attaches a long-lived uprobe, streams captured credentials, and keeps the probe running until `--disable`. It uses no ptrace, breakpoints, or temporary files.

The loader can map any `.so` a module declares or supplies, including raw bytes provided by the script.

### Windows tokens and Kerberos

On Windows, emp3r0r can use an access token from another process for Go modules, Starlark, and BOFs. Modules accept `--token` for an existing token, `--user` for a disposable netonly session, and `--ticket` for a Kerberos ticket.

A netonly session keeps the agent's local identity and borrows the target user only for outbound authentication. A ticket can be imported into the same session, so the network identity becomes the ticket's identity while the local process stays unchanged. Because the session is disposable, the credential material can be purged when the operation is done.

### Pivoting

The C2 can run a SOCKS5 listener that relays through an agent. The operator can use it from inside the WireGuard tunnel or start `tun2socks` with a route. For example:

```text
socks_start 1080
tun2socks start --route 10.10.0.0/24
```

Only the listed subnet goes through the agent. Everything else keeps using the operator's normal connection. Tools that do not support a proxy can still reach the agent-side network.

### C2 transport

Agents can use beacon-style HTTP polling, streaming HTTP/2, or a QUIC UDP channel. HTTP/2 and QUIC are build-time options (`with_h2conn`, `with_quic`). QUIC obfuscates datagrams with a per-build key by default. The `--quic-standard-key` flag disables that and speaks stock QUIC.

HTTP polling uses a malleable request profile from the C2 config. TLS fingerprints can be randomized with uTLS. Behind an ECH-capable CDN, `--doh` and `--ech` hide the inner SNI from the ClientHello. Control messages use CBOR rather than JSON.

### Modular agent builds

Agent features are selected at build time with `with_*` tags. The installer builds a slim kit by default: Linux and Windows amd64 agents with plain HTTP polling and no optional subsystems. `--full` builds every target and every feature. `--agent-tags` selects an exact feature set, and `--list-agent-tags` prints the available tags.

C2 server binaries keep the full feature set, so one server can handle every agent variant.

### Experimental C agent

There is an experimental C agent for Linux. Its executable is around 100 KB. The beacon contains only the core C2 protocol. Everything else, including crypto, compression, transport, dynamic loading, and the BOF loader, is modular. Runtime libraries and the BOF loader are loaded on demand, used, then removed from memory, just as the Go agent handles its dependencies.

```bash
generate_c --type glibc --arch amd64 --cc your.domain.com
```

### Encrypted memory storage

Agent file operations use an in-memory AES-GCM encrypted filesystem. Large files spill to disk only as encrypted blobs with no identifying headers. Agents that take part in the P2P mesh cache files in this filesystem and share them with peers.

## Quick start

See [OPERATOR.md](./OPERATOR.md) for installation, operator setup, container notes, tmux keybindings, and agent generation.

## Documentation

- [Operator guide](./OPERATOR.md)
- [Module development guide](./core/modules/module_development_guide.md)
- [Testing guide](./TESTING.md)
- [Security policy](./SECURITY.md)
- [Changelog](./CHANGELOG.md)

## Support

If emp3r0r is useful in your security research or testing, you can support development through [GitHub Sponsors](https://github.com/sponsors/jm33-m0).
