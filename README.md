<img align="left" width="150" height="150" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

### emp3r0r

**A self-healing, memory-only C2 for Linux and Windows — agents that survive broken links, never touch disk, and script their way through the Win32 API.**

<br clear="all" />

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/jm33-m0/emp3r0r?filename=core%2Fgo.mod)
[![Tests](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml/badge.svg)](https://github.com/jm33-m0/emp3r0r/actions/workflows/test.yml)
![GitHub License](https://img.shields.io/github/license/jm33-m0/emp3r0r)
[![GitHub release](https://img.shields.io/github/release/jm33-m0/emp3r0r.svg)](https://github.com/jm33-m0/emp3r0r/releases)

---

<img width="1908" height="1141" alt="emp3r0r operator console screenshot" src="https://github.com/user-attachments/assets/8952f405-2af9-4840-b57f-086498f389b8" />

## What is emp3r0r?

emp3r0r is a post-exploitation framework and C2 built for Linux and Windows environments where stealth and resilience aren't optional. Instead of assuming a reliable connection back to one server, agents form a self-healing mesh that keeps working when links break. Instead of asking the target for Python or PowerShell, they execute everything in memory. And instead of limiting you to one platform's tricks, emp3r0r runs Windows BOFs, Linux objects, and Starlark scripts — all fileless, all in-process.

---

## Key Highlights & Unique Features

### 🐍 Scriptable Agents (Embedded Starlark Engine & Win32 API Proxy)

Every agent carries its own scripting engine, so you can drop in new post-exploitation logic without compiling or shipping binaries.

- Scripts run entirely in memory — no Python, Bash, or PowerShell required on the target, and no command interpreters spawned.
- A full set of built-in APIs covers file I/O, HTTP, command execution, and more, straight from script code.
- On Windows, scripts can call native Win32 functions directly — the agent proxies straight into system DLLs.
- Modules are plain Starlark files with a small JSON manifest, so adding your own is easy and fileless.

**Why this matters:** writing and extending agent functionality becomes as simple as editing a script, with none of the footprint of dropping an interpreter or a new binary on the target.

---

### 🔐 TOFU Cryptographic Identity Pinning

Agents bind their identity to a cryptographic key the first time they talk to you — and that binding never changes.

- Re-enrollment with different credentials is treated as an impostor and rejected.
- Removing an agent is an explicit operator decision, not something a stolen key can do quietly.

**Why this matters:** session hijacking and agent cloning simply don't happen; every agent you talk to is the one you enrolled.

---

### 🔒 Perfect Forward Secrecy (PFS)

Every C2 and peer link uses ephemeral ECDH keys with session-derived encryption keys.

**Why this matters:** even if a long-term key is compromised later, it can't be used to decrypt traffic that already passed.

---

### 🕸️ Autonomous P2P Gossip Mesh Network

Agents discover each other and relay traffic through a gossip mesh, so the operation doesn't collapse when one link or one server disappears.

- Peers connect over camouflage mTLS 1.3 or reliable UDP (KCP), with every hop encrypted.
- Traffic routes around dead relays automatically — no manual proxy surgery mid-operation.
- Segments with no direct C2 access still stay reachable through their neighbors.

**Why this matters:** the network does the pivoting for you. Cut a link, lose a box, or block the C2 — agents re-route on their own.

---

### 📂 P2P Filesystem

Files move between agents directly, not just through the C2.

- Transfers ride encrypted peer-to-peer tunnels, so internal networks don't bottleneck on your server.
- Files are cached in agent memory as encrypted blobs and served to peers on demand.
- If no peer has a file, the agent fetches it from the C2 automatically.

**Why this matters:** delivery is fast and mostly invisible to the C2 channel — ideal for egress-restricted environments.

---

### 📡 Multi-Protocol Listeners & Pluggable Stagers

Getting an agent in is treated as seriously as keeping it alive.

- HTTP, TCP, and UDP listeners with reliable framing and customizable HTTP profiles.
- A roughly 2KB stager built on direct Linux syscalls — no libc, no toolchain on the target.
- Pluggable stager transports and self-unpacking packers let you blend initial access into whatever channel your target allows, and defeat static signature matching along the way.
- Stage and agent code respect read/write/execute discipline — never RWX.

**Why this matters:** small, adaptable, and memory-hygienic initial access means you can land on hosts that would otherwise be out of reach.

---

### 🧩 Native Cross-Platform BOF & PICO Support (COFF, ELF & PICO)

Run compiled C modules in-process on either platform:

- Windows COFF/BOF binaries with typed argument packing.
- Linux ELF relocatable objects loaded straight into agent memory.
- Crystal-Kit PICO modules with SilentMoonwalk callstack spoofing.
- Kerbeus-BOF, Remote-OPs, and a Situational Awareness suite ship ready to use.

**Why this matters:** BOFs are only as good as their loader — emp3r0r runs them in-process with no new process and no trace left behind, on both Linux and Windows.

---

### 🔑 Windows Tokens, Netonly Sessions & Kerberos Tickets (PTT)

Once you're on a Windows host, emp3r0r lets you *become* the users on it — without ever dropping a tool.

- Steal an access token from any running process and use it everywhere: Go modules, Starlark, BOFs.
- Create disposable netonly sessions (`make_token`) that keep your agent's own identity and only borrow the target user's for outbound access — any password works, nothing is ever validated.
- Import Kerberos tickets (`import_ticket`) into those sessions for full pass-the-ticket: your network identity becomes the ticket's (say, the Domain Admin) while your local identity never changes.
- Every module accepts `--token`, `--user`, and `--ticket`, so switching identity is one flag away — including creating a session and loading a ticket in a single command.
- Tickets live per logon session, so the DA material stays quarantined in a disposable session you can purge, and the agent process itself stays clean.

**Why this matters:** lateral movement to machines running no agent at all — SMB shares, service control, CIFS — becomes a normal part of your workflow, authenticated as the user you've borrowed, not as a tool on disk.

---

### 🧦 SOCKS5 Pivoting & Operator-Side tun2socks

Pivot without burning another implant: the C2 runs a SOCKS5 proxy that relays through the agent you select, and the operator side can go one step further with a transparent TUN device.

- `socks_start 1080` gives you a SOCKS5 endpoint on the C2 that tunnels through the chosen agent — point proxychains or any tool at it and you're inside the target network.
- `tun2socks start --route 10.10.0.0/24` creates a TUN device that routes only the subnets you name through that proxy — everything else keeps using your normal connection.
- The result looks like it originates from the agent, with no per-tool proxy configuration.

**Why this matters:** reach entire agent-side networks transparently — curl a DC, use any tool — with egress that appears to come from the target network, not your operator box.

---

### 🎭 Pluggable C2 Transport, uTLS JA3 Evasion & CBOR Protocol

- Choose beacon-style HTTP polling or streaming HTTP/2 — both with malleable profiles.
- TLS fingerprints are randomized with uTLS, so the channel doesn't stand out in network telemetry.
- Control traffic rides a compact CBOR protocol — smaller, faster, and harder to parse than JSON.

**Why this matters:** the C2 channel is made to look like ordinary traffic and stay lean on the wire.

---

### 💾 Encrypted Memory-First Storage

- Agent file operations run against an in-memory, AES-GCM-encrypted virtual filesystem; large data spills to disk only as encrypted blobs with no identifiable headers.
- P2P-capable agents cache what they fetch and share it with peers, shrinking C2 traffic further.

**Why this matters:** even disk is treated as hostile — the agent keeps no plaintext artifacts around to find.

---

## Quick Start

### 1. C2 Server Installation

Building emp3r0r requires Docker or Podman on the host — no local Go toolchain.

```bash
git clone --depth=1 https://github.com/jm33-m0/emp3r0r.git && cd emp3r0r
./install.py
```

The installer builds everything in a throwaway container and prepares the operator kit. Useful flags: `--lightweight` (Linux/Windows amd64 only, fastest), `--targets OS/ARCH,...`, `--debug`, `--skip-build`.

Launch the server:

```bash
emp3r0r server --c2-hosts 1.2.3.4 --http-port 12345 --operator-port 13377
```

### 2. Operator Machine Setup

```bash
tar --zstd -xpf emp3r0r-operator-kit.tar.zst
cd ./emp3r0r-operator-kit && ./install.py
```

Connect using the WireGuard credentials the server printed:

```bash
emp3r0r client --c2-port 13377 \
  --server-wg-key '<SERVER_WG_KEY>' --server-wg-ip '<SERVER_WG_IP>' \
  --operator-wg-ip '<OPERATOR_WG_IP>' --operator-wg-key '<OPERATOR_WG_KEY>' \
  --c2-host 1.2.3.4
```

### 3. Generate Agent Payloads

Inside the operator console:

```bash
# Direct C2 agent
generate --type linux_executable --arch amd64 --cc your.domain.com

# Mesh gateway agent (also reachable from the C2 directly)
generate --type linux_executable --arch amd64 --cc your.domain.com \
  --p2p --direct-c2 --p2p-transport mtls

# Mesh intermediate peer (relays for other agents)
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
