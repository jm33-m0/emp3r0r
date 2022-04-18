# emp3r0r
Linux/Windows post-exploitation framework made by linux user

## current state

**emp3r0r C2 (Linux and Windows) is ready for testing, please report bugs if you find any**

- read the [wiki](https://github.com/jm33-m0/emp3r0r/wiki) to get started
- download from [here](https://github.com/jm33-m0/emp3r0r/releases)
- [write modules](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r) for emp3r0r, with your favorite languages
- Windows support is ready, with fully-interactive shell <details><summary>view screenshot</summary>![image](https://user-images.githubusercontent.com/10167884/162661854-a52fc5bc-b322-4099-8a06-8f2aaa76b3ea.png)</details>

![image](https://user-images.githubusercontent.com/10167884/163743855-6639c6aa-9b3a-4891-8845-1505236ac026.png)

<details><summary>more screenshots / videos</summary>

https://user-images.githubusercontent.com/10167884/155106403-ca6bd763-7f09-4aae-adc3-67f7a36f99ad.mp4

![image](https://user-images.githubusercontent.com/10167884/158535621-6c0ecbc5-47cb-4ad2-bbf6-4e625eef1f84.png)

![c2](./img/c2transports.png)

</details>

----------

## how it started

emp3r0r was initially developed as one of my weaponizing experiments, i tried to implement common Linux adversary techniques and some of my own ideas, it was a learning process for me

what makes emp3r0r different? well, first of all, its the first C2 framework that targets Linux platform, and you can use basically any other tools through it. if you need more reasons to try it out, check [features](#features)

emp3r0r also has complete [**python3.9 support**](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r#python), that is less than 7MB with necessary third party packages such as `requests` and `mysql`

----------

## features

* beautiful terminal UI, use [tmux](https://github.com/tmux/tmux) for window management
* multi-tasking, you don't need to wait for any commands to finish
* module support: provide [**python3.9** environment](https://github.com/jm33-m0/emp3r0r/releases/tag/v1.3.10), easily run your exploits/tools on any linux host
* **perfect shell experience** via SSH, compatible with any SSH client, also available for **Windows**
* [**bettercap**](https://github.com/bettercap/bettercap)
* [**built-in static bash binary**](https://github.com/jm33-m0/emp3r0r/blob/master/core/lib/data/bash.go)
* auto **persistence** via various methods
* [**post-exploitation tools**](https://github.com/jm33-m0/emp3r0r/tree/master/core/modules/vaccine) like nmap, socat
* **credential harvesting** (WIP)
* [process **injection**](https://jm33.me/emp3r0r-injection.html)
* [**shellcode** injection](https://jm33.me/process-injection-on-linux.html)
* ELF **patcher** (WIP)
* [**packer**](https://github.com/jm33-m0/emp3r0r/tree/master/packer) that encrypts and compresses agent binary, and runs agent in a covert way
* **hide processes and files** (WIP)
* **port mapping**, from c2 side to agent side, and vice versa
* agent side socks5 **proxy**
* [**auto root**](https://github.com/jm33-m0/go-lpe)
* **LPE** suggest
* system info collecting
* file management, **resumable download/upload**
* log cleaner
* screenshot
* **stealth** connection
* anti-antivirus
* internet access checker
* **autoproxy** for semi-isolated networks
* **reverse proxy** to bring every host online
* all of these in **HTTP2**
* painlessly encapsulated in **Shadowsocks and KCP**
* can be encapsulated in any external proxies such as [**TOR**, and **CDNs**](https://github.com/jm33-m0/emp3r0r/raw/master/img/c2transports.png)
* [interoperability with **metasploit / Cobalt Strike**](https://github.com/jm33-m0/emp3r0r/wiki/Interoperability-with-metasploit-and-other-C2-frameworks)
* [**custom modules**](https://github.com/jm33-m0/emp3r0r/wiki/Write-modules-for-emp3r0r)
* and many more...
