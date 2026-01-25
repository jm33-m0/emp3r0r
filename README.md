<img align="left" width="150" height="150" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

### emp3r0r

**A powerful Linux/Windows post-exploitation framework designed by Linux users, for Linux environments**

<br clear="all" />

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)
[![Screenshots](https://img.shields.io/badge/View-Screenshots-blue?style=for-the-badge)](./Screenshots.md)

[![Go Report Card](https://goreportcard.com/badge/gojp/goreportcard)](https://goreportcard.com/report/github.com/jm33-m0/emp3r0r/core)
[![Go Version](https://img.shields.io/github/go-mod/go-version/jm33-m0/emp3r0r?filename=core/go.mod)](https://github.com/jm33-m0/emp3r0r/blob/v3/core/go.mod)
[![Build Status](https://github.com/jm33-m0/emp3r0r/actions/workflows/release-please.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/release-please.yml)
[![Tests](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml)
[![License](https://img.shields.io/github/license/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/blob/v3/LICENSE)
[![GitHub release](https://img.shields.io/github/release/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/releases)

---

## SSH Credential Harvesting in Action

<https://github.com/user-attachments/assets/e735b325-d9ad-43bd-b34d-79f395cc4b8f>

---

## What is emp3r0r?

emp3r0r is a comprehensive post-exploitation framework that stands out as one of the first C2 platforms purpose-built for Linux environments. While most frameworks treat Linux as an afterthought, emp3r0r puts it front and center, delivering robust capabilities for penetration testing and red team operations across both Linux and Windows targets.

### Why emp3r0r?

- **Linux-Native Architecture**: Built from the ground up for Linux targets with full Windows compatibility.
- **Universal Module Support**: Execute Bash, PowerShell, Python, DLL, SO, and EXE modules seamlessly across platforms.
- **Advanced Stealth**: **Memory-backed agent file system** with transparent encryption, in-memory module execution, BOF-like modules on both Windows and Linux, advanced Linux stagers, and DLL/Shellcode agents for flexible deployment.
- **Modern Infrastructure**: WireGuard + mTLS operator authentication, HTTP2/TLS with **JA3 fingerprinting evasion**, KCP-based UDP tunneling.
- **COFF/BOF Loader**: Native BOF execution on Windows agents with typed argument packing (LPSTR/LPWSTR/INT/BOOL/BINARY), powered by [praetorian-inc/goffloader](https://github.com/praetorian-inc/goffloader), and integration-friendly module schema; on Linux you can load ELF object files in-memory to achieve the same effect.
- **APT-Grade Connectivity**: **Auto-Proxy Chain** creates a resilient, automatic P2P mesh network. Agents in air-gapped or isolated segments autonomously discover and piggyback on internet-connected peers to reach the C2, ensuring long-term survival in hardened environments.
- **Bring2CC**: Reverse proxy any target port to the C2 server, enabling direct access to internal resources even when agents cannot make outbound connections.

---

## Quick Start

### Installation

```bash
curl -sSL https://raw.githubusercontent.com/jm33-m0/emp3r0r/refs/heads/v3/install.sh | bash
```

### 3-Step Deployment

#### Initialize the Server

```bash
emp3r0r server --c2-hosts 'your.domain.com' --port 12345 --operators 2
```

This command deploys emp3r0r with:

- HTTP2/TLS agent listener on a randomized port.
- WireGuard operator service.
- Operator mTLS server.

#### Connect as Operator

Copy the generated connection command and replace `<C2_PUBLIC_IP>` with your server's IP:

```bash
emp3r0r client --c2-port 12345 --server-wg-key 'key...' --c2-host your.domain.com
```

#### Generate Agent Payloads

Use the `generate` command from within the emp3r0r shell interface to create customized agent payloads.

---

## Core Capabilities

### Stealth & Evasion

#### OpSec Safety & File Operations

- **Memory-first approach** with intelligent storage management to minimize disk presence.
- **Minimal footprint** with no dedicated agent directories or persistent files.
- **Warn-before-write** for operations that touch disk, keeping hosts clean.
- **Consistent artifacts** via uniform file handling for predictable, low-profile operations.

#### Advanced Process Hiding

- **Obfuscated processes** and hidden helpers to lower visibility.
- **Anti-debug/analysis** measures to make inspection harder.
- **sRDI-like Shellcode Stager**: Load ELF binaries from memory without touching disk, similar to sRDI for Windows.
- **Memory-backed Agent Filesystem**: Agents use an in-memory file system with transparent encryption for file operations. Large files automatically spill to encrypted disk storage when memory limits are reached, balancing stealth with resource efficiency.

#### Secure Command & Control

- **JA3-evasive HTTP2/TLS** ([uTLS](https://github.com/refraction-networking/utls): Randomizes TLS Client Hello fingerprints to evade JA3-based detection systems
- **WireGuard+mTLS** for secure operator access.
- **KCP** for speed and resilience in high-latency environments
- **TOR/CDN** support for additional operational cover.

### Operator Experience

#### Professional CLI Interface

- **Console + Cobra core** for robust command handling.
- **Intelligent auto-completion** with syntax highlighting.
- **Native tmux integration** for parallel operations.
- **BYOS (Bring Your Own Shell)**: SSH-based reverse PTY that drives any shell available on the target (bash, zsh, sh, python REPL, etc.) over the same tunnel you also reuse for the file manager and transfers.

#### Advanced Shell Integration

- **SSH PTY** for native terminal experience.
- **Windows-compatible** with standard OpenSSH clients.
- **SFTP integration** for efficient remote file operations.

#### File Transfer System

- **Bidirectional Transfer**: Upload files to agents (`put`) and download from agents (`get`) with intuitive commands.
- **Recursive Downloads**: Download entire directories with `--recursive` flag and filter files using regex patterns (`--regex`).
- **Smart Transfer Strategy**: Agents can fetch files from peer agents via encrypted KCP tunnels before falling back to C2, improving speed and stealth.
- **Integrity & Reliability**: SHA256 verification plus **resumable uploads/downloads** so interrupted transfers continue from the last offset.
- **Real-Time Monitoring**: Progress bars display transfer speed, completion percentage, and estimated time remaining.
- **Compression**: Zstandard compression reduces bandwidth usage and accelerates transfers.
- **FileServer Module**: Agents can host an encrypted HTTP server to share files with other agents, enabling peer-to-peer distribution.
- **Security**: All transfers occur over HTTP2/TLS connections with lock file protection to prevent concurrent access.

### Network Pivoting

#### Intelligent Network Traversal

- **Automatic P2P Mesh**: Agents autonomously form a mesh network using UDP broadcasts and rolling tags. Agents in air-gapped or isolated networks automatically find and tunnel through internet-connected peers (via Shadowsocks), creating a resilient, self-healing command path typical of advanced APT implants.
- **Bring2CC**: A reverse proxy mechanism (SSH + KCP) that tunnels any port from the agent (or its network) back to the C2 server. This beats the isolation where agents cannot make outbound connections, effectively "bringing" the target to the Command & Control server.
- **Flexible Pivoting**: Bi-directional TCP/UDP port mapping and agent-side Socks5 (with UDP) support.

### Payload Delivery

#### Flexible Staging Options

- Multi-stage delivery for Linux and Windows with ELF/DLL/shellcode options.
- Windows DLL/shellcode agents for loader-friendly drops; Linux shared-library stager for stealthy starts.
- **Built-in listener module** supports HTTP, TCP, and UDP protocols for agent-side payload hosting during lateral movement.

#### Advanced Linux Stager (Outcome-Focused)

- Keeps the agent payload encrypted until the moment of execution, avoiding plaintext on disk.
- Watches the agent and auto-restarts with jitter when connectivity/policy requires, so access recovers without manual action.
- Ships with safe defaults to prevent self-deletion or noisy argv changes when invoked by the stager.
- Supports multiple listener protocols (HTTP/TCP/UDP) via compile-time configuration.

#### Agent-Side Listener for Lateral Movement

- Deploy listeners on compromised hosts to serve payloads internally, bypassing slow C2 connections.
- Supports `http_aes_compressed`, `tcp_aes_compressed`, and `udp_aes_compressed` for encrypted payload delivery.
- Ideal for rapid agent propagation within target networks without external communication.

#### In-Memory Execution

- **All modules execute in-memory** - Bash, PowerShell, Python, and native ELF modules run directly from the agent's memory-backed file system.
- Execute ELF objects (.o) or executables entirely in memory on Linux targets.
- Memory-only loaders and injection paths eliminate disk artifacts.
- ELF patcher module lets you graft the agent into existing binaries when needed.

### Post-Exploitation Arsenal

#### Credential Harvesting

- OpenSSH credential harvesting with real-time monitoring (`ssh_harvester`).
- Cross-platform memory dumping capabilities (`mem_dump`).
- Windows mini-dump extraction (pypykatz compatible).

#### Additional Capabilities

- **Screenshot**: Fully integrated module for capturing target screens.
- **LPE**: Privilege escalation tools with automated suggestions (`lpe_suggest`).
- **Log Sanitization**: `clean_log` module for anti-forensics.

---

## Documentation & Support

### Community

Join our [Discord server](https://discord.gg/vU98aQtk9f) for real-time discussions, technical support, and the latest updates on emp3r0r development.

### Resources

- 📸 [Screenshots and Videos](./Screenshots.md)
- 📋 [Features Overview](./FEATURES.md)
- 📝 [Security Policy](./SECURITY.md)
- 📜 [Changelog](./CHANGELOG.md)
- 📦 [Module Development (including COFF/BOF)](./emp3r0r.wiki/Modules.md)

### Troubleshooting

- **Connection stalls**: Verify C2 host/WireGuard settings.
- **Compatibility**: Remove `~/.emp3r0r` for a clean install.

> **Note**: Cross-version compatibility is not guaranteed.

---

## Support Development

If emp3r0r has proven valuable in your security research and testing, consider supporting its continued development via [GitHub Sponsors](https://github.com/sponsors/jm33-m0).
