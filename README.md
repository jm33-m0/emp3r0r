<img align="left" width="150" height="150" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

### emp3r0r

**Self‑healing Gossip Mesh C2 with Assisted Peer Discovery, Cross-Platform BOF Execution, and Scriptable Agents.**

<br clear="all" />

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/jm33-m0/emp3r0r?filename=core%2Fgo.mod)
[![Tests](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml)
![GitHub License](https://img.shields.io/github/license/jm33-m0/emp3r0r)
[![GitHub release](https://img.shields.io/github/release/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/releases)

---

<img width="2560" height="1392" alt="image" src="https://github.com/user-attachments/assets/264e7752-aef6-4451-aca6-db29b1d45f78" />

## What is emp3r0r?

emp3r0r is an advanced, zero-trust post-exploitation framework and command & control (C2) system designed for Linux and Windows target environments. Built from the ground up to operate in high-security environments, emp3r0r combines **autonomous gossip mesh networking**, **fileless memory-only execution**, **cross-platform BOF loading**, **inter-agent file transfer**, and **in-memory scriptable agents** to deliver superior stealth, operational control, and operational security (OPSEC).

---

## Key Highlights & Unique Features

### 🐍 Scriptable Agents (Embedded Starlark Engine & Win32 API Proxy)

emp3r0r agents feature an embedded **Starlark scripting engine** (a Python dialect implemented purely in Go). Scripts execute filelessly in memory without requiring Python, Bash, or PowerShell installed on the target.

- **Zero Host Dependencies:** Executes standalone scripts without spawning command interpreters (`/bin/sh`, `powershell.exe`) or relying on installed runtimes.
- **Built-in Agent Go APIs:** Exposed functions for filesystem operations (`read_file`, `write_file`, `list_dir`, `mkdir`, `remove`, `exists`), HTTP networking (`http_get`, `http_post`), command execution (`exec_cmd`), and hashing (`crypto_hash`).
- **Dynamic Win32 API Proxy:** On Windows targets, Starlark scripts can dynamically load system DLLs and execute native Win32 APIs (`win_call`, `win_alloc`, `win_free`, `win_read_mem`) directly from script code without compiling native C code.
- **Modular Integration:** Starlark scripts are defined using JSON manifests (`config.json`) for seamless CLI parameter parsing and distribution.

**Why this matters:** Traditional C2 script modules require host interpreters or process spawning, leaving heavy disk or command-line execution traces. emp3r0r's scriptable agents execute complex logic entirely in memory with native system interaction.

---

### 🔐 TOFU Cryptographic Identity Pinning

emp3r0r enforces **Trust-On-First-Use (TOFU)** with strict UUID and public-key pinning upon agent enrollment.

- **Immutable Binding:** Once enrolled, an agent's UUID is pinned to its cryptographic public key. Re-enrollment with altered credentials is rejected as an impersonation attempt.
- **Controlled Reset:** De-registration requires explicit operator authorization via `forget_agent`.

**Why this matters:** Prevents session hijacking, agent cloning, and silent identity drift across operational environments.

---

### 🔒 Perfect Forward Secrecy (PFS)

All C2 and peer communications enforce **ECDH key exchange** with **HKDF-derived session keys**.

- **Ephemeral Keys:** Each session generates unique encryption keys.
- **Decoupled Security:** Compromising long-term keys or an individual agent cannot compromise past or parallel communications.

**Why this matters:** Prevents retrospective decryption of intercepted network captures.

---

### 🕸️ Autonomous P2P Gossip Mesh Network

Agents in egress-restricted or isolated network segments autonomously discover peers and tunnel traffic via a gossip-based (Memberlist) mesh network.

- **Pluggable Peer Transports:** Support for camouflage **mTLS 1.3** (using ephemeral certificates) and **KCP** (reliable UDP).
- **End-to-End Encryption:** All inter-agent mesh hops are wrapped in AES-GCM encryption.
- **Low Network Footprint:** Direct agent-to-agent relaying eliminates unnecessary broadcast noise and centralized C2 connection chokepoints.

**Why this matters:** Pivoting across segmented networks occurs autonomously without requiring constant operator intervention or static proxy setups.

---

### 📂 Inter-Agent Peer-to-Peer File Transfer

Direct agent-to-agent file sharing via P2P relay transport (mYLS/KCP) to accelerate file delivery across internal networks.

- **Encrypted P2P Tunnels:** Tunnel transfers across peers using mTLS/KCP to bypass egress restrictions and reduce central C2 bandwidth bottlenecks.
- **Smart In-Memory File Caching**: Files are cached in agent memory as encrypted blobs; can be seamlessly served for other agents to download on-demand. When requesting a file, agents look at their local memfs, then other peers, finally the C2.
- **Automatic C2 Relay Fallback:** If a target peer lacks the requested file, it dynamically fetches and streams it from the C2 server on-demand.

**Why this matters:** Direct agent-to-agent file sharing maximizes transfer speeds, bypasses network chokepoints, and reduces direct C2 traffic visibility.

---

### 📡 Multi-Protocol Listeners & Stagers

Flexible Stage 0 downloader stagers and protocol listeners for initial access and payload delivery.

- **Multi-Protocol Listeners:** Embedded and standalone HTTP, TCP, and UDP listeners with reliable sequence-acknowledgment framing and custom HTTP profiles.
- **Standalone C Downloader Stager:** Built with direct, libc-independent Linux syscalls for compatibility across distributions without symbol errors.
- **Flexible Formats:** Compiles into raw position-independent shellcode (`.bin`), standalone ELF executables, or shared objects (`.so`).
- **In-Memory Hardening:** Allocates stage memory with read-write permissions, de-obfuscates payloads, and enforces read-execute (`mprotect`) prior to reflectively executing Stage 1.

---

### 🧩 Native Cross-Platform BOF Support (COFF & ELF)

Execute in-memory binary modules on both Windows and Linux targets:

- **Windows COFF Loaders:** Run Windows BOF binaries filelessly with typed parameter packing (`int`, `short`, `cstr`, `wstr`, `binary`).
- **Linux ELF Object Loaders:** Load ELF relocatable object files (`.o`) directly into agent memory on Linux.
- **Bundled BOF Suites:** Built-in support for Kerbeus-BOF, Remote-OPs, and Situational Awareness (SA) module collections.

**Why this matters:** Eliminates process creation overhead and circumvents command-line monitoring by running compiled C modules in-process.

---

### 🎭 Pluggable C2 Transport, uTLS JA3 Evasion & CBOR Protocol

- **Pluggable C2 Modes:** Flexible beaconing (`http_poll`) with malleable HTTP profiles and streaming (`h2conn`) over HTTP/2.
- **JA3 Signature Randomization:** Utilizes **uTLS** to randomize TLS Client Hello fingerprints, defeating static network signatures.
- **Binary Wire Protocol:** Uses **CBOR** (Concise Binary Object Representation) for all control data and wire serialization, reducing network payload sizes by 30-40% compared to JSON.

---

### 💾 Encrypted Memory-First Storage & OPSEC Safeguards

- **In-Memory Encrypted Virtual Filesystem:** All agent file operations use an in-memory AES-GCM virtual filesystem. Large data automatically spills to encrypted disk storage without identifiable headers or extensions.
- **Stealth & Evasion:** sRDI-like ELF stagers, module stomping, and self-suspension with XOR-rotated memory obfuscation during idle states.

---

## Quick Start

### 1. C2 Server Installation

Building emp3r0r requires Docker or Podman on the host. No local Go toolchain is required.

```bash
# Clone repository
git clone --depth=1 https://github.com/jm33-m0/emp3r0r.git && cd emp3r0r

# Build inside a container and install locally
./install.sh
```

The installer compiles the core binaries inside a throwaway container, generates the precompiled `emp3r0r-operator-kit.tar.zst`, configures required Linux capabilities (`setcap`), and sets up system runtime directories.

Options:

```bash
./install.sh [--debug] [--disable-garble] [--prefix /usr/local] [--skip-build]
```

Launch the C2 server:

```bash
emp3r0r server --c2-hosts 1.2.3.4 --http-port 12345 --operator-port 13377
```

---

### 2. Operator Machine Setup

Transfer the generated `emp3r0r-operator-kit.tar.zst` to your operator machine and run the installer:

```bash
tar --zstd -xpf emp3r0r-operator-kit.tar.zst
cd ./emp3r0r-operator-kit && ./install.sh
```

Connect the operator client to the C2 server using the WireGuard tunnel credentials printed by the server:

```bash
emp3r0r client --c2-port 13377 \
  --server-wg-key '<SERVER_WG_KEY>' \
  --server-wg-ip '<SERVER_WG_IP>' \
  --operator-wg-ip '<OPERATOR_WG_IP>' \
  --operator-wg-key '<OPERATOR_WG_KEY>' \
  --c2-host 1.2.3.4
```

---

### 3. Generate Agent Payloads

Use the `generate` command within the emp3r0r operator interface to create payloads.

**Direct C2 Agent:**

```bash
generate --type linux_executable --arch amd64 --cc your.domain.com
```

**Mesh Gateway Agent:**

```bash
generate --type linux_executable --arch amd64 --cc your.domain.com \
  --p2p --direct-c2 --p2p-transport mtls
```

**Mesh Intermediate Peer:**

```bash
generate --type linux_executable --arch amd64 --cc your.domain.com \
  --p2p --p2p-transport mtls --peers 1.2.3.4
```

---

## Documentation & Resources

- 📝 **Security Policy:** [SECURITY.md](./SECURITY.md)
- 📜 **Changelog:** [CHANGELOG.md](./CHANGELOG.md)
- 🛠️ **Module Development Guide:** [core/modules/module_development_guide.md](./core/modules/module_development_guide.md)

---

## Support Development

If emp3r0r has proven valuable in your security research and testing, consider supporting its continued development via [GitHub Sponsors](https://github.com/sponsors/jm33-m0).
