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

https://user-images.githubusercontent.com/10167884/120208162-bfc56b00-c25f-11eb-8062-9b96c625c0df.mp4


<!-- vim-markdown-toc GFM -->

* [why another post-exploitation tool?](#why-another-post-exploitation-tool)
* [features](#features)
* [what to expect (in future releases)](#what-to-expect-in-future-releases)

<!-- vim-markdown-toc -->

----------

## why another post-exploitation tool?

why not? i dont see many post-exploitation frameworks for linux systems, even if there were, they are nothing like mine

as a linux user, the most critical thing for remote administration is **terminal**. if you hate the garbage reverse shell experience (sometimes it aint even a shell), take a look at emp3r0r, you will be impressed

yes i just want to make a post-exploitation tool for linux users like me, who want better experience in their hacking

another reason is compatibility. as emp3r0r is mostly written in [Go](https://golang.org), and fully static (so are all the plugins used by emp3r0r), it will run everywhere (tested on Linux 2.6 and above) you want, regardless of the shitty environments. in some cases you wont even find bash on your target, dont worry, emp3r0r uploads its own [bash](https://github.com/jm33-m0/static-bins/tree/main/vaccine) and many other useful tools

why is it called `emp3r0r`? because theres an [empire](https://github.com/BC-SECURITY/empire)

i hope this tool helps you, and i will add features to it as i learn new things

## features

* beautiful terminal UI, use tmux for window management
* multi-tasking, you don't need to wait for any commands to finish
* basic API provided through unix socket
* **perfect reverse shell** (true color, key bindings, custom bashrc, custom bash binary, etc)
* auto **persistence** via various methods
* **post-exploitation tools** like nmap, socat, are integreted with reverse shell
* **credential harvesting** (WIP)
* process **injection**
* **shellcode** injection and dropper
* ELF **patcher**
* **hide processes and files** via libc hijacking
* **port mapping**, from c2 side to agent side, and vice versa
* agent side socks5 **proxy**
* **ssh server**
* auto root
* **LPE** suggest
* system info collecting
* file management, **resumable download**
* log cleaner
* screenshot
* **stealth** connection
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
