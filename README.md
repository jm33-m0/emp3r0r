# emp3r0r

A post-exploitation framework for Linux/Windows

<https://github.com/user-attachments/assets/70076b47-044b-4f83-87f9-9a7996f32025>

[More Screenshots and videos](./Screenshots.md)

---

## How to use

Read the [wiki](https://github.com/jm33-m0/emp3r0r/wiki/Getting-started) to get started. Please also consider contributing your own documentation there to help others.

## Motivation

Initially, emp3r0r was developed as one of my weaponizing experiments. It was a learning process for me trying to implement common Linux adversary techniques and some of my original ideas.

**So, what makes emp3r0r different?** First of all, it is the first C2 framework that targets Linux platform including the capability of using any other tools through it. Take a look at the [features](#features) for more valid reasons to use it.

To support third-party modules, emp3r0r has complete [python3 support](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r#python), included in [`vaccine`](./core/modules/vaccine) module, 15MB in total, with necessary third party packages such as `Impacket`, `Requests` and `MySQL`.

---

## Features

- Beautiful Terminal UI
  - Use [tmux](https://github.com/tmux/tmux) for window management
- Stealth
  - Automatically changes `argv` so you won't notice it in `ps` listing
  - Hide files and PIDs via Glibc hijacking (`patcher` in `get_persistence`)
  - Built-in [**Elvish Shell**](https://elv.sh/) with the same disguise as main process
  - [**Bring Your Own Shell**](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r#vaccine) or any interactive programs via [custom modules such as bettercap](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r#module-metadata)
  - All C2 communications made in HTTP2/TLS
  - Defeat [**JA3**](https://github.com/salesforce/ja3) fingerprinting with [**UTLS**](https://github.com/refraction-networking/utls)
  - Painlessly encapsulated in **Shadowsocks** and KCP
  - Able to encapsulate in any external proxies such as [**TOR** and **CDN**s](https://github.com/jm33-m0/emp3r0r/raw/master/img/c2transports.png)
  - [**C2 relaying**](https://github.com/jm33-m0/emp3r0r/wiki/C2-Relay) via SSH
- Staged Payload Delivery for both Linux and Windows
  - [HTTP Listener with AES and compression](https://github.com/jm33-m0/emp3r0r/wiki/Listener)
  - [**DLL agent**](https://github.com/jm33-m0/emp3r0r/wiki/DLL-Agent), [**Shellcode agent**](https://github.com/jm33-m0/emp3r0r/wiki/Shellcode-Agent-for-Windows) for Windows targets and [**Shared Library stager**](https://github.com/jm33-m0/emp3r0r/wiki/Shared-Library-Stager-for-Linux) for Linux
- Automatically bridge agents from internal networks to C2 using **Shadowsocks proxy chain**
  - For semi-isolated networks, where agents can negotiate and form a proxy chain
- Any reachable targets can be (reverse) proxied out via SSH and stealth KCP tunnel
  - [**Bring any targets you can reach to C2**](https://github.com/jm33-m0/emp3r0r/wiki/Getting-started#bring-agents-to-c2)
  - Useful when targets can't establish outgoing connections but can accept incoming requests
- Multi-Tasking
  - Don't have to wait for any commands to finish
- Module Support
  - Provides [**python3** environment](https://github.com/jm33-m0/emp3r0r/releases/tag/v1.3.10) that can easily run your exploits/tools on any Linux host
  - [Custom Modules](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r)
- Perfect Shell Experience via **SSH with PTY support**
  - Compatible with any SSH client and **available for Windows**
- [Bettercap](https://github.com/bettercap/bettercap)
- Auto persistence via various methods
- [Post-exploitation Tools](https://github.com/jm33-m0/emp3r0r/tree/master/core/modules/vaccine)
  - Nmap, Socat, Ncat, Bettercap, etc
- Credential Harvesting
  - [**OpenSSH password harvester**](https://github.com/jm33-m0/emp3r0r/blob/master/core/lib/agent/ssh_harvester_amd64_linux.go)
- [Process Injection](https://jm33.me/emp3r0r-injection.html)
- [Shellcode Injection](https://jm33.me/process-injection-on-linux.html)
- ELF Patcher for persistence
- [Packer](https://github.com/jm33-m0/emp3r0r/tree/master/packer)
  - Encrypts and compresses agent binary and runs agent in a covert way
- Hide processes and files and get persistence via shared library injection
- Networking
  - Port Mapping
    - From C2 side to agent side, and vice versa
    - TCP/UDP both supported
  - Agent Side Socks5 Proxy with UDP support
- [Auto Root](https://github.com/jm33-m0/go-lpe)
- LPE Suggest
- System Info Collect
- File Management
  - Enables **resumable downloads/uploads**
  - SFTP support: browse remote files with any SFTP client, [including your local **GUI file manager**](https://github.com/jm33-m0/emp3r0r/releases/tag/v1.22.3)
- Log Cleaner
- Screenshot
- Anti-Antivirus
- Internet Access Checker
- and many more :)
