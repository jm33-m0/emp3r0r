# emp3r0r
A post-exploitation framework for Linux/Windows

## Status

**emp3r0r C2 (Linux/Windows) is ready for testing. Please report bugs if you find any.**
- Read [wiki](https://github.com/jm33-m0/emp3r0r/wiki) to get started
- Download from [here](https://github.com/jm33-m0/emp3r0r/releases)
- [Write modules](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r) for emp3r0r with your favorite languages
- Windows support is ready with fully-interactive shell 

<details><summary> VIEW screenshots</summary>
  
![image](https://user-images.githubusercontent.com/10167884/162661854-a52fc5bc-b322-4099-8a06-8f2aaa76b3ea.png)

![image](https://user-images.githubusercontent.com/10167884/163743855-6639c6aa-9b3a-4891-8845-1505236ac026.png)</details>

<details><summary> MORE screenshots/videos</summary>

https://user-images.githubusercontent.com/10167884/155106403-ca6bd763-7f09-4aae-adc3-67f7a36f99ad.mp4

![image](https://user-images.githubusercontent.com/10167884/158535621-6c0ecbc5-47cb-4ad2-bbf6-4e625eef1f84.png)

![c2](./img/c2transports.png)

</details>

----------

## Motivation

Initially, emp3r0r was developed as one of my weaponizing experiments. It was a learning process for me trying to implement common Linux adversary techniques and some of my original ideas.

**So, what makes emp3r0r different?** First of all, it is the first C2 framework that targets Linux platform including the capability of using any other tools through it. Take a look at the [features](#features) for more valid reasons to use it.

In fact, emp3r0r has complete [python3.9 support](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r#python), which is less than 7MB with necessary third party packages such as `Requests` or `MySQL`.

----------

## Features
* Beautiful Terminal UI
  * Use [tmux](https://github.com/tmux/tmux) for window management
* Multi-Tasking
  * Don't have to wait for any commands to finish
* Module Support
  * Provides [python3.9 environment](https://github.com/jm33-m0/emp3r0r/releases/tag/v1.3.10) that can easily run your exploits/tools on any Linux host
* Perfect Shell Experience via SSH
  * Compatible with any SSH client and available for Windows
* [Bettercap](https://github.com/bettercap/bettercap)
* [Built-in Static Bash Binary](https://github.com/jm33-m0/emp3r0r/blob/master/core/lib/data/bash.go)
* Auto persistence via various methods
* [Post-exploitation Tools](https://github.com/jm33-m0/emp3r0r/tree/master/core/modules/vaccine) 
  * Similar to Nmap, Socat
* Credential Harvesting (WIP)
* [Process Injection](https://jm33.me/emp3r0r-injection.html)
* [Shellcode Injection](https://jm33.me/process-injection-on-linux.html)
* ELF Patcher (WIP)
* [Packer](https://github.com/jm33-m0/emp3r0r/tree/master/packer)
  * Encrypts and compresses agent binary and runs agent in a covert way
* Hide processes and files (WIP)
* Port Mapping
  * From C2 side to agent side, and vice versa
* Agent Side: Socks5 Proxy
* [Auto Root](https://github.com/jm33-m0/go-lpe)
* LPE Suggest
* System Info Collect
* File Management
  * Enables resumable downloads/uploads
* Log Cleaner
* Screenshot
* Stealth Connection
* Anti-Antivirus
* Internet Access Checker
* Autoproxy 
  * For semi-isolated networks
* Reverse Proxy
  * To bring every host online
* All of these in HTTP2
* Painlessly encapsulated in Shadowsocks and KCP
* Able to encapsulate in any external proxies such as [TOR and CDNs](https://github.com/jm33-m0/emp3r0r/raw/master/img/c2transports.png)
* [Interoperability with Metasploit/Cobalt Strike](https://github.com/jm33-m0/emp3r0r/wiki/Interoperability-with-metasploit-and-other-C2-frameworks)
* [Custom Modules](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r)
* and many more :)
