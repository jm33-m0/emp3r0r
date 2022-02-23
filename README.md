# emp3r0r
Linux/Windows post-exploitation framework made by linux user

**Still under active development**

- [screenshots](./FEATURES.md)
- [check my blog for updates](https://jm33.me)
- [how to use](https://github.com/jm33-m0/emp3r0r/wiki)


![UI](https://user-images.githubusercontent.com/10167884/155084808-fb0df1ef-6eab-4894-8af0-81934e9cd25e.png)

https://user-images.githubusercontent.com/10167884/155106403-ca6bd763-7f09-4aae-adc3-67f7a36f99ad.mp4

![c2](./img/c2transports.png)

----------

emp3r0r was initially developed as one of my weaponizing experiments, i tried to implement common Linux adversary techniques and some of my own ideas, it was a learning process for me

what makes emp3r0r different? well, first of all, its the first C2 framework that targets Linux platform, and you can use basically any other tools through it. if you need more reasons to try it out, check [features](./FEATURES.md)

the name *emp3r0r* comes from [empire](https://github.com/BC-SECURITY/Empire/) project

currently emp3r0r has limited Windows support

----------

* beautiful terminal UI, use tmux for window management
* multi-tasking, you don't need to wait for any commands to finish
* basic API provided through unix socket
* **perfect reverse shell** (true color, key bindings, custom bashrc, custom bash binary, etc)
* **built-in static bash binary**
* auto **persistence** via various methods
* **post-exploitation tools** like nmap, socat, are integreted with reverse shell
* **credential harvesting** (WIP)
* process **injection**
* **shellcode** injection and dropper
* ELF **patcher** (WIP)
* **packer** that encrypts and compresses agent binary, and runs agent in a covert way
* **hide processes and files** via libc hijacking (WIP)
* **port mapping**, from c2 side to agent side, and vice versa
* agent side socks5 **proxy**
* **ssh server**
* auto root (WIP)
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
* **custom modules**
* and many more...
