# emp3r0r
linux post-exploitation framework made by linux user

**Still under active development**

- [features](./FEATURES.md)
- [中文介绍](https://www.freebuf.com/sectool/259079.html)
- [check my blog for updates](https://jm33.me/emp3r0r-0x00.html)
- [how to use](https://github.com/jm33-m0/emp3r0r/wiki)
- **collaborators wanted!!!** please [contact me](https://jm33.me/pages/got-something-to-say.html) if you are interested
- **cross-platform** support is in progress, contribute if you want emp3r0r to run on other systems
- feel free to develop your **private version** of emp3r0r, and i would appreciate that you contribute back to this branch


https://user-images.githubusercontent.com/10167884/120104002-eebade80-c184-11eb-820c-30fd3da9db41.mp4

----------

## features

* beautiful terminal UI, use tmux for window management
* multi-tasking, you don't need to wait for any commands to finish
* basic API provided through unix socket
* **perfect reverse shell** (true color, key bindings, custom bashrc, custom bash binary, etc)
* auto **persistence** via various methods
* **post-exploitation tools** like nmap, socat, are integreted with reverse shell
* **credential harvesting**
* process **injection**
* **shellcode** injection and dropper
* ELF **patcher**
* **hide processes and files** via libc hijacking
* port mapping, socks5 **proxy**
* auto root
* **LPE** suggest
* system info collecting
* file management, **resumable download
* log cleaner
* screenshot
* **stealth** connection
* screenshot
* anti-antivirus
* internet access checker
* **autoproxy** for semi-isolated networks
* **reverse proxy** to bring every host online
* all of these in one **HTTP2** connection
* can be encapsulated in any external proxies such as **TOR**, and **CDNs**
* interoperability with **metasploit / Cobalt Strike**
* and many more...

## what to expect (in future releases)

- [x] packer: cryptor + `memfd_create`
- [x] packer: use `shm_open` in older Linux kernels
- [x] dropper: shellcode injector - python
- [x] port mapping: forward from CC to agents, so you can use encapsulate other tools (such as Cobalt Strike) in emp3r0r's CC tunnel
- [x] randomize everything that can be randomized (file path, port number, etc)
- [x] injector: shellcode loader, using python2
- [x] injector: inject shellcode into arbitrary process, using go and ptrace syscall
- [x] injector: recover process after injection
- [x] persistence: inject guardian shellcode into arbitrary process to gain persistence
- [x] **headless CC**, control using existing commands, can be useful when we write a web-based GUI
- [x] screenshot, supports both windows and linux
- [x] reverse proxy
- [x] better file manager
- [x] resumable download/upload
- [x] screenshot
- [x] **better shells!**
- [ ] network scanner
- [ ] passive scanner, for host/service discovery
- [ ] password spray
- [ ] auto pwn using weak credentials and RCEs
