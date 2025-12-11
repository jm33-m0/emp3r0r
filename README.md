# emp3r0r

<img width="200" height="200" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />

**A powerful Linux/Windows post-exploitation framework designed by Linux users, for Linux environments**

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)
[![Screenshots](https://img.shields.io/badge/View-Screenshots-blue?style=for-the-badge)](./Screenshots.md)

---

## SSH Credential Harvesting in Action

<https://github.com/user-attachments/assets/e735b325-d9ad-43bd-b34d-79f395cc4b8f>

---

## What is emp3r0r?

emp3r0r is a comprehensive post-exploitation framework that stands out as one of the first C2 platforms purpose-built for Linux environments. While most frameworks treat Linux as an afterthought, emp3r0r puts it front and center, delivering robust capabilities for penetration testing and red team operations across both Linux and Windows targets.

### Why emp3r0r?

- **Linux-Native Architecture**: Built from the ground up for Linux targets with full Windows compatibility.
- **Extensible Python Environment**: Deploy a complete Python3 runtime with Impacket, Requests, and MySQL libraries via the `vaccine` module.
- **Universal Module Support**: Execute Bash, PowerShell, Python, DLL, SO, and EXE modules seamlessly across platforms.
- **Advanced Stealth**: Dynamic process obfuscation, file concealment, time-stomping, and **lazy initialization** (filesystem modifications only on demand).
- **Modern Infrastructure**: WireGuard + mTLS operator authentication, HTTP2/TLS with JA3 evasion, KCP-based UDP tunneling.

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

- **OpSec Safety & File Operations**
  - **Fileless Warnings**: The C2 automatically warns operators when a selected module is about to drop files on the target disk, preventing accidental OpSec failures.
  - **Lazy Initialization**: Agent directories (e.g., `AgentRoot`) are created **only on demand**, reducing the agent's filesystem footprint on startup.
  - **Unified File Hooks**: All agent file operations utilize centralized wrappers (`WriteFileAgent`, etc.), allowing for custom naming patterns and behavior hooks for all dropped artifacts.
  - **Stealthy Artifacts**: Temporary files and lock files use generic suffixes (`.tmp`, `.lock`).

- **Advanced Process Hiding**
  - Dynamic `argv` manipulation to obfuscate process listings.
  - File and PID concealment via Glibc hijacking techniques.
  - Anti-debugging and anti-analysis countermeasures.

- **Secure Command & Control**
  - HTTP2/TLS with UTLS implementation to defeat JA3 fingerprinting.
  - KCP-based fast, multiplexed UDP tunneling for high-performance operations.
  - Native TOR and CDN proxy support for anonymization.
  - WireGuard + mTLS for operator authentication and secure channels.

### Operator Experience

- **Professional CLI Interface**
  - Built on console and cobra frameworks for robust command handling.
  - Intelligent auto-completion with syntax highlighting.
  - Native tmux integration for parallel operations.
  - **ByoS (Bring Your Own Shell)**: Full `elvish` shell compatibility.

- **Advanced Shell Integration**
  - SSH with full PTY support for native terminal experience.
  - Windows compatibility with standard OpenSSH clients.
  - SFTP integration for efficient remote file operations.

- **File Transfer System**
  - **Bidirectional Transfer**: Upload files to agents (`put`) and download from agents (`get`) with intuitive commands.
  - **Recursive Downloads**: Download entire directories with `--recursive` flag and filter files using regex patterns (`--regex`).
  - **Smart Transfer Strategy**: Agents can fetch files from peer agents via encrypted KCP tunnels before falling back to C2, improving speed and stealth.
  - **Integrity & Reliability**: SHA256 checksum verification ensures file integrity; resume support allows interrupted transfers to continue from the last offset.
  - **Real-Time Monitoring**: Progress bars display transfer speed, completion percentage, and estimated time remaining.
  - **Compression**: Zstandard compression reduces bandwidth usage and accelerates transfers.
  - **FileServer Module**: Agents can host an encrypted HTTP server to share files with other agents, enabling peer-to-peer distribution.
  - **Security**: All transfers occur over HTTP2/TLS connections with lock file protection to prevent concurrent access.

### Network Pivoting

- **Intelligent Network Traversal**
  - Automatic agent bridging through Shadowsocks proxy chains.
  - Reverse proxy capabilities via SSH and KCP tunnels (`bring2cc`).
  - External target access for otherwise unreachable endpoints.
  - Bidirectional port mapping supporting both TCP and UDP protocols.
  - Agent-side Socks5 proxy with full UDP support.

### Payload Delivery

- **Flexible Staging Options**
  - Multi-stage payload delivery for both Linux and Windows.
  - HTTP listener with AES encryption and compression.
  - DLL agent and shellcode agent for Windows environments.
  - Shared library stager for Linux targets.

- **In-Memory Execution**
  - Execute Bash, PowerShell, Python, and native ELF binaries without touching disk.
  - CGO-based ELF loader for memory-only execution.
  - Process injection and shellcode injection capabilities.
  - **ELF Patcher**: Patch arbitrary ELF binaries to load the agent payload (`elf_patch` module).

### Post-Exploitation Arsenal

- **Credential Harvesting**
  - OpenSSH credential harvesting with real-time monitoring (`ssh_harvester`).
  - Cross-platform memory dumping capabilities (`mem_dump`).
  - Windows mini-dump extraction (pypykatz compatible).

- **Additional Capabilities**
  - **Screenshot**: Fully integrated module for capturing target screens.
  - **Vaccine**: Deploy a complete Python3 runtime, nmap, socat, and other tools.
  - **Persistence**: Multiple mechanisms including cron jobs, shell profiles, and binary patching.
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

### Troubleshooting

- **Connection stalls**: Verify C2 host/WireGuard settings.
- **Compatibility**: Remove `~/.emp3r0r` for a clean install.

> **Note**: Cross-version compatibility is not guaranteed.

---

## Support Development

If emp3r0r has proven valuable in your security research and testing, consider supporting its continued development via [GitHub Sponsors](https://github.com/sponsors/jm33-m0).
