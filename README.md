<img align="left" width="150" height="150" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

### emp3r0r

**Self‑healing Gossip Mesh C2 with Assisted Peer Discovery, Modular Post‑Exploitation, and Scriptable Agents.**

<br clear="all" />

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)
[![Screenshots](https://img.shields.io/badge/View-Screenshots-blue?style=for-the-badge)](./Screenshots.md)

[![Go Report Card](https://goreportcard.com/badge/gojp/goreportcard)](https://goreportcard.com/report/github.com/jm33-m0/emp3r0r/core)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/jm33-m0/emp3r0r?filename=core%2Fgo.mod)
[![Tests](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml)
![GitHub License](https://img.shields.io/github/license/jm33-m0/emp3r0r)
[![GitHub release](https://img.shields.io/github/release/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/releases)

---

<img width="2560" height="1392" alt="image" src="https://github.com/user-attachments/assets/264e7752-aef6-4451-aca6-db29b1d45f78" />

## What is emp3r0r?

emp3r0r is a comprehensive post-exploitation framework designed from the ground up for Linux environments. While most C2 platforms treat Linux as an afterthought, emp3r0r implements a **zero-trust architecture** with ephemeral cryptographic identities, perfect forward secrecy, and autonomous mesh networking for penetration testing and red team operations.

## What Makes emp3r0r Different?

### 🔐 TOFU Identity Pinning (Immutable per Enrollment)

emp3r0r enforces **Trust-on-first-use (TOFU)** with strict UUID/public-key pinning on first successful enrollment. After enrollment, the pinned identity is immutable for that lifecycle: if the same UUID appears with a different key, the connection is rejected as clone/impersonation. Re-enrollment with changed credentials requires a deliberate `forget_agent` first.

**Why this matters:** This blocks silent identity drift and session hijacking patterns. Trust comes from CA-signed claims plus pinned DB state, not mutable runtime metadata.

### 🔒 Perfect Forward Secrecy for All Communications

Every C2 session uses **ECDH key exchange** with **HKDF-derived session keys**. Past traffic remains secure even if long-term keys or agents are compromised. Each session's encryption keys are unique and cannot be derived from other sessions.

**Why this matters:** Traditional C2s use static encryption keys. If those keys are recovered, historical network captures can be decrypted. emp3r0r's PFS ensures that compromising today's session keys doesn't reveal previous communications.

### 🕸️ Peer-to-Peer (P2P) Mesh Network

Agents in isolated network segments **autonomously discover and tunnel through internet-connected peers** via a gossip-based (memberlist) mesh network. The mesh hop transport is **pluggable**: the default is `mtls` — camouflage mTLS 1.3 using ephemeral, malleable certificates — with `kcp` (reliable UDP) also available. All hops are further wrapped in AES-GCM end-to-end encryption. **No unnecessary noise** in your C2 infrastructure: agents connect to each other instead of C2 server; **no broadcasting**; configurable bootstrap peers allowing granular control.

**Why this matters:** Manual pivoting requires constant operator intervention and breaks when intermediate hosts fail. emp3r0r's agents automatically form redundant communication paths, ensuring persistence through resilient peer discovery and relay.

### 💾 Memory-Only Operations with Transparent Encryption

Agents use an **in-memory filesystem with AES-GCM encryption** for all file operations. Bash, PowerShell, Python, Starlark, and ELF modules execute entirely from memory. Large files automatically spill to **encrypted disk storage** when memory is exhausted. The agent creates no dedicated directories or persistent configuration files.

**Why this matters:** EDR and forensic tools rely on disk artifacts for detection and analysis. emp3r0r's memory-first design minimizes disk writes. When disk spillover occurs, all data is encrypted and lacks identifying file extensions or headers.

### 🐍 In-Memory Scripting via Starlark (No Python Required)

emp3r0r embeds a **Starlark scripting engine** (a dialect of Python implemented in Go) directly inside the agent. Scripts execute entirely in memory without spawning new processes or requiring Python, Bash, or PowerShell to be installed on the target machine.

**Why this matters:** Traditional script modules require local interpreters, leaving footprints on disk or in command histories. emp3r0r's Starlark engine runs scripts in-memory with built-in Go APIs for filesystem access, network communication, process enumeration, and system execution.

### 🧩 Native BOF Support (Cross-Platform)

Execute **Windows COFF objects** on Windows agents with typed argument packing (LPSTR/LPWSTR/INT/BOOL/BINARY). On Linux, load **ELF object files (.o)** entirely in-memory with the same modularity. Modules use a standardized schema for cross-platform consistency.

**Why this matters:** BOFs avoid process creation overhead and are difficult to detect. emp3r0r brings this capability to Linux, where most C2 frameworks rely on forking processes or interpreting shell scripts.

### 🎭 Pluggable C2 Transport + JA3 Evasion + CBOR

emp3r0r supports **pluggable C2 channel wrappers**. In v4, the default is `http_poll` beacon mode, and `h2conn` stream mode is also available. `http_poll` runs over HTTP/1.1 with malleable profiles and can be proxied by CDN/reverse proxies directly, without the websocket `--cdn2proxy` bridge.

HTTP2/TLS connections use **uTLS** to randomize TLS Client Hello fingerprints, preventing static JA3 signature detection. All network traffic and data storage uses **CBOR** (binary) instead of JSON, reducing bandwidth by 30-40% and avoiding text-based parsing signatures.

**Why this matters:** Network monitoring tools fingerprint TLS handshakes for application identification. Static TLS implementations create consistent signatures. emp3r0r randomizes these on every connection while using a compact binary protocol that lacks JSON's obvious structure.

---

## Quick Start

### Install on C2 Server

Requires Docker (or Podman) on the host. No Go toolchain needed.

```bash
# Clone the project
git clone --depth=1 https://github.com/jm33-m0/emp3r0r.git && cd emp3r0r

# Build inside a throwaway Docker container, then install locally
./install.sh
```

`install.sh` will:

1. Pull the official `golang:1.26.2` image and compile emp3r0r inside it from the **local repository**
2. Produce `core/emp3r0r-operator-kit.tar.zst` containing all precompiled binaries (including `emp3r0r-listener`) and data files
3. Extract that operator kit locally and invoke its bundled installer to automatically configure permissions (`setcap`), create WireGuard run directories (`tmpfiles.d`), and install shell autocompletions on the host

Options:

```
./install.sh [--debug] [--disable-garble] [--prefix /usr/local] [--skip-build]
```

Use `--skip-build` to skip the Docker compilation step entirely and reinstall/reconfigure using the cached operator kit from a previous build.

Then start the C2 server:

```bash
emp3r0r server --c2-hosts 1.2.3.4 --http-port 12345 --operator-port 13377
```

### Operator Machine Setup

After the C2 server prints its connection command, transfer the operator kit and run its bundled installer:

```bash
# On your operator machine
tar --zstd -xpf emp3r0r-operator-kit.tar.zst
./emp3r0r-operator-kit/install.sh    # handles setcap, WireGuard dir, and shell completion automatically
```

Then run the connection command printed by the C2 server:

```bash
emp3r0r client --c2-port 13377 --server-wg-key '0OKqMZmJfLDhAQLST4MKtKNa6MKxVkLn3UcOP14sMA8=' --server-wg-ip '10.88.14.158' --operator-wg-ip '10.88.14.236' --operator-wg-key 'LOe4sUyjyyIS3Kjnmz0SpKJwvDGle0880Q73qzsMg48=' --c2-host 1.2.3.4
```

`emp3r0r client` automatically downloads and applies config files from C2 server via WireGuard tunnel.

### Generate Agent Payloads

Use the `generate` command from within the emp3r0r shell interface to create customized agent payloads.

Example (standalone direct C2):

```bash
generate --type linux_executable --arch amd64 --cc your.domain.com
```

Example (mesh gateway):

The gateway peer:

```bash
generate --type linux_executable --arch amd64 --cc your.domain.com \
	--p2p --direct-c2 --p2p-transport mtls
```

An intermediate peer:

```bash
# 1.2.3.4 is the pre-existing agent node that you want to use as bootstrap peer
generate --type linux_executable --arch amd64 --cc your.domain.com \
	--p2p --p2p-transport mtls --peers 1.2.3.4
```

---

## Additional Capabilities

### Stealth & Evasion

- **sRDI-like Shellcode Stager**: Load ELF binaries from memory without touching disk, similar to sRDI for Windows.
- **Self-suspension & Resumption**: Agents can suspend themselves and let the stager manage their memory; the stager rotates XOR-based obfuscation while the agent is idle.
- **Module Stomping**: Disguise malicious modules by loading them into the memory space of legitimate system libraries.
- **OPSEC Warnings**: Real-time warnings for operations that pose operational security risks (e.g., "fork and run" patterns, unencrypted disk activity).
- **Embedded Starlark Scripting**: Execute Python-like scripts entirely in memory on the agent via the built-in Go Starlark interpreter, removing dependencies on target host interpreters.
- **Anti-debug/analysis** measures to make inspection harder.

### Operator Experience

- **Adaptive tmux UI**: Native integration with dynamic status bars, adaptive layouts, and real-time agent/C2 status monitoring.
- **Intelligent auto-completion** with syntax highlighting.
- **Pluggable Frontend**: Develop your own frontend by replicating `operator` package features.

### File Transfer System

- **Smart Transfer Strategy**: Agents can fetch files from peer agents via encrypted KCP tunnels before falling back to C2, improving speed and stealth.
- **Integrity & Reliability**: SHA256 verification plus **resumable uploads/downloads** so interrupted transfers continue from the last offset.
- **Compression**: Zstandard compression reduces bandwidth usage and accelerates transfers.
- **FileServer Module**: Agents can host an encrypted HTTP server to share files with other agents, enabling peer-to-peer distribution.

### Network Pivoting

- **Flexible Pivoting**: Gossip mesh relay plus reverse-tunnel workflows for segmented networks.
- **KCP-based UDP tunneling** for speed and resilience in high-latency environments.
- **TOR/CDN** support for additional operational cover.

### Payload Delivery

- **Advanced Linux Stager**: 1.5K self-contained stage0 downloader; opsec focused; keeps the agent payload encrypted until execution; auto-restarts with jitter when connectivity requires.
- **Agent-Side Listener**: Deploy listeners on compromised hosts to serve payloads internally, bypassing slow C2 connections.
- **Multi-stage delivery** for Linux and Windows with ELF/DLL/shellcode options.

### Post-Exploitation Arsenal

- **OpenSSH credential harvesting** with real-time monitoring (`ssh_harvester`).
- **Cross-platform memory dumping** capabilities (`mem_dump`).
- **LPE**: Privilege escalation tools with automated suggestions (`lpe_suggest`).
- **Log Sanitization**: `clean_log` module for anti-forensics.

---

## Documentation & Support

### Community

Join our [Discord server](https://discord.gg/vU98aQtk9f) for real-time discussions, technical support, and the latest updates on emp3r0r development.

### Resources

- 📝 [Security Policy](./SECURITY.md)
- 📜 [Changelog](./CHANGELOG.md)
- 🛠️ [Module Development Guide (COFF/BOF & Starlark)](./core/modules/module_development_guide.md)

### Troubleshooting

- **Connection stalls**: Verify C2 host/WireGuard settings.
- **Compatibility**: Remove `~/.emp3r0r` for a clean install; make sure to use the same build.
- **Support**: Always use the latest release to get support.

---

## Support Development

If emp3r0r has proven valuable in your security research and testing, consider supporting its continued development via [GitHub Sponsors](https://github.com/sponsors/jm33-m0).
