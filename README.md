<img align="left" width="150" height="150" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

### emp3r0r

**Zero-Trust C2: Ephemeral TOFU + PFS + Auto-Proxy Mesh + Memory-Only Ops + Bring2CC + Native BOF**

<br clear="all" />

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)
[![Screenshots](https://img.shields.io/badge/View-Screenshots-blue?style=for-the-badge)](./Screenshots.md)

[![Go Report Card](https://goreportcard.com/badge/gojp/goreportcard)](https://goreportcard.com/report/github.com/jm33-m0/emp3r0r/core)
[![Go Version](https://img.shields.io/github/go-mod/go-version/jm33-m0/emp3r0r?filename=core/go.mod)](https://github.com/jm33-m0/emp3r0r/blob/v3/core/go.mod)
[![Tests](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml)
[![License](https://img.shields.io/github/license/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/blob/v3/LICENSE)
[![GitHub release](https://img.shields.io/github/release/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/releases)

---

<img width="2560" height="1392" alt="image" src="https://github.com/user-attachments/assets/4ce74add-695f-4572-9a19-b6954856c73f" />

## What is emp3r0r?

emp3r0r is the first post-exploitation framework designed from the ground up for Linux environments with **APT-level operational security**. While traditional C2 platforms treat Linux as an afterthought, emp3r0r implements a comprehensive **zero-trust architecture** with cryptographic primitives and autonomous networking that rival nation-state malware.

## What Makes emp3r0r Different?

### 🔐 Ephemeral TOFU Identity (Unique to emp3r0r)

Agent identities are **generated per-session** using ECDSA P-256 and **lost on restart**—no static credentials to extract from disk or memory dumps. **Trust-on-first-use (TOFU)** authentication prevents impersonation: the C2 "pins" the agent's public key on first check-in, and subsequent connections must prove possession of the same ephemeral key. Key rotation requires manual operator approval, making agent hijacking nearly impossible.

**Why this matters:** Most C2 frameworks bake agent credentials into binaries. If an agent is captured, adversaries can extract keys and impersonate it indefinitely. emp3r0r's ephemeral keys exist only in process memory and disappear on reboot.

### 🔒 Perfect Forward Secrecy for All Communications

Every C2 session uses **ECDH key exchange** with **HKDF-derived session keys**. Past traffic remains secure even if long-term keys or agents are compromised—a rarity in the C2 space. Combined with ephemeral agent identities, this creates **defense-in-depth** against forensic analysis.

**Why this matters:** Traditional C2s use static encryption keys. If blue team captures those keys, they can decrypt historical PCAP traffic. emp3r0r's PFS ensures that compromise of today's session doesn't reveal yesterday's commands.

### 🕸️ Self-Healing P2P Mesh Network (Auto-Proxy Chain)

Agents in isolated network segments **autonomously discover and tunnel through internet-connected peers** via Shadowsocks, creating resilient command paths without manual pivoting configuration. The mesh network **self-heals** like APT implants—if one proxy fails, agents automatically find alternative routes to C2.

**Why this matters:** Manual pivoting is tedious and fragile. emp3r0r's agents form a dynamic mesh using UDP broadcasts and rolling tags, ensuring long-term survival in segmented enterprise networks. This is APT-grade connectivity in a red team tool.

### 🚪 Bring2CC: Reverse Tunneling for Isolated Targets

When agents **cannot** make outbound connections, **Bring2CC** reverse-proxies them back to the C2 server using SSH + KCP tunneling—effectively "bringing" isolated targets to your infrastructure. This bypasses egress filtering and enables access to air-gapped segments via compromised jump hosts.

**Why this matters:** Traditional C2s fail when egress is blocked. Bring2CC inverts the problem: instead of reaching into the network, you pull the network out to yourself. Combine this with Auto-Proxy Mesh for unstoppable connectivity.

### 💾 Memory-Only Operations with Transparent Encryption

Agents use an **in-memory filesystem with AES-GCM encryption** for all file operations. Bash, PowerShell, Python, and ELF modules execute entirely from memory. Large files automatically spill to **encrypted disk storage** when memory is exhausted, balancing stealth with resource efficiency. The agent binary itself contains no dedicated directories or persistent files.

**Why this matters:** EDR and forensic tools look for disk artifacts. emp3r0r's memory-first approach leaves minimal trace. Even when disk spillover occurs, files are encrypted and indistinguishable from random data.

### 🧩 Native BOF Support (Cross-Platform)

Execute **Windows COFF objects** on Windows agents with typed argument packing (LPSTR/LPWSTR/INT/BOOL/BINARY). On Linux, load **ELF object files (.o)** entirely in-memory with the same modularity. This brings the flexibility of Cobalt Strike's BOF ecosystem to both platforms, with an integration-friendly module schema.

**Why this matters:** BOFs are compact, fast, and avoid process creation. emp3r0r extends this capability to Linux, where most C2s still rely on shell scripts or full binaries.

### 🎭 JA3 Fingerprint Evasion + CBOR Serialization

HTTP2/TLS connections use **uTLS** to randomize TLS Client Hello fingerprints, evading JA3-based detection. All network traffic and data storage uses **CBOR** (binary) instead of JSON, reducing bandwidth and avoiding signature-based detection on JSON parsing patterns.

**Why this matters:** Modern EDR/NDR systems fingerprint TLS handshakes. Static TLS implementations create detectable patterns. emp3r0r randomizes these fingerprints on every connection while using a compact binary protocol that's harder to inspect.

---

## Quick Start

### Installation

While pre-built binaries may be available, building from source is the primary and recommended installation method:

```bash
# Automated install script (Installs dependencies and builds from source)
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

## Additional Capabilities

### Stealth & Evasion

- **sRDI-like Shellcode Stager**: Load ELF binaries from memory without touching disk, similar to sRDI for Windows.
- **Self-suspension & Resumption**: Agents can suspend themselves and let the stager manage their memory; the stager rotates XOR-based obfuscation while the agent is idle.
- **Module Stomping**: Disguise malicious modules by loading them into the memory space of legitimate system libraries.
- **OPSEC Warnings**: Real-time warnings for operations that pose operational security risks (e.g., "fork and run" patterns, unencrypted disk activity).
- **Anti-debug/analysis** measures to make inspection harder.

### Operator Experience

- **Adaptive tmux UI**: Native integration with dynamic status bars, adaptive layouts, and real-time agent/C2 status monitoring.
- **BYOS (Bring Your Own Shell)**: SSH-based reverse PTY that drives any shell available on the target (bash, zsh, sh, python REPL, etc.) over the same tunnel you also reuse for file manager and transfers.
- **Intelligent auto-completion** with syntax highlighting.
- **SFTP integration** for efficient remote file operations.

### File Transfer System

- **Smart Transfer Strategy**: Agents can fetch files from peer agents via encrypted KCP tunnels before falling back to C2, improving speed and stealth.
- **Integrity & Reliability**: SHA256 verification plus **resumable uploads/downloads** so interrupted transfers continue from the last offset.
- **Compression**: Zstandard compression reduces bandwidth usage and accelerates transfers.
- **FileServer Module**: Agents can host an encrypted HTTP server to share files with other agents, enabling peer-to-peer distribution.

### Network Pivoting

- **Flexible Pivoting**: Bi-directional TCP/UDP port mapping and agent-side Socks5 (with UDP) support.
- **KCP-based UDP tunneling** for speed and resilience in high-latency environments.
- **TOR/CDN** support for additional operational cover.

### Payload Delivery

- **Advanced Linux Stager**: Keeps the agent payload encrypted until execution; auto-restarts with jitter when connectivity requires.
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

- 📸 [Screenshots and Videos](./Screenshots.md)
- 📋 [Features Overview](./FEATURES.md)
- 📝 [Security Policy](./SECURITY.md)
- 📜 [Changelog](./CHANGELOG.md)
- 📦 [Module Development (including COFF/BOF)](https://github.com/jm33-m0/emp3r0r/wiki/Modules)

### Troubleshooting

- **Connection stalls**: Verify C2 host/WireGuard settings.
- **Compatibility**: Remove `~/.emp3r0r` for a clean install.

> **Note**: Cross-version compatibility is not guaranteed.

---

## Support Development

If emp3r0r has proven valuable in your security research and testing, consider supporting its continued development via [GitHub Sponsors](https://github.com/sponsors/jm33-m0).
