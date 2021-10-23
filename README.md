# emp3r0r
linux post-exploitation framework made by linux user

**Still under active development**

- [screenshots](./FEATURES.md)
- [check my blog for updates](https://jm33.me)
- [how to use](https://github.com/jm33-m0/emp3r0r/wiki)

----------

emp3r0r was initially developed as one of my weaponizing experiments, i tried to implement common Linux adversary techniques and some of my own ideas, it was a learning process for me

what makes emp3r0r different? well, first of all, its the first C2 framework that targets Linux platform, and you can use basically any other tools through it. if you need more reasons to try it out, check [features](./FEATURES.md)

the name *emp3r0r* comes from [empire](https://github.com/BC-SECURITY/Empire/) project

https://user-images.githubusercontent.com/10167884/122037656-5d479f80-ce07-11eb-96af-4b4d2c06c61b.mp4

----------

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
* **packer** that encrypts and compresses agent binary, and runs agent in a covert way
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
