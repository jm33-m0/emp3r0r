# Changelog

## [1.22.3](https://github.com/jm33-m0/emp3r0r/compare/v1.22.2...v1.22.3) (2022-10-01)


### Bug Fixes

* sftp improvements ([80deffd](https://github.com/jm33-m0/emp3r0r/commit/80deffdca98541e0a873a59452424cdbec61d656))
* sftp pane not opening ([82e2fc5](https://github.com/jm33-m0/emp3r0r/commit/82e2fc5269e3c137eac7e2b60e5f27ce4cfa5210))

## [1.22.2](https://github.com/jm33-m0/emp3r0r/compare/v1.22.1...v1.22.2) (2022-09-30)


### Bug Fixes

* broken shell pane for windows targets ([3cbd03a](https://github.com/jm33-m0/emp3r0r/commit/3cbd03a1ea9fec077a6d16210ef49cbe5d95345f))

## [1.22.1](https://github.com/jm33-m0/emp3r0r/compare/v1.22.0...v1.22.1) (2022-09-30)


### Bug Fixes

* tmux pane resizing issues ([7849902](https://github.com/jm33-m0/emp3r0r/commit/78499022d53ccdc5060e76388d49f91c2b1c76e6))

## [1.22.0](https://github.com/jm33-m0/emp3r0r/compare/v1.21.0...v1.22.0) (2022-09-30)


### Features

* sftp support ([9b84eb9](https://github.com/jm33-m0/emp3r0r/commit/9b84eb929eea7687e0f9bf05df37802592f02126))

![image](https://user-images.githubusercontent.com/10167884/193186205-44c9e201-b3d0-4ced-b955-ad07c4f49de3.png)


## [1.21.0](https://github.com/jm33-m0/emp3r0r/compare/v1.20.0...v1.21.0) (2022-09-29)


### Features

* autocomplete items in PATH on target system ([a1a6268](https://github.com/jm33-m0/emp3r0r/commit/a1a626810fff3aac06cc3119b1b4cfa710109332))


### Bug Fixes

* empty agent uuid ([416aadc](https://github.com/jm33-m0/emp3r0r/commit/416aadcec61ada4f1dbf2020ad2f78afcfd04fdd))
* fail to check command output from agent, agent then gets marked as unresponsive incorrectly ([14553b6](https://github.com/jm33-m0/emp3r0r/commit/14553b6251f8beefda676a96b9f090c3a5c40bab))
* lengthy log ([a3e2f72](https://github.com/jm33-m0/emp3r0r/commit/a3e2f72321febcd18529cb3861e51cbe918761d3))
* screenshot downloading fails ([886e864](https://github.com/jm33-m0/emp3r0r/commit/886e864679bd91590e576e0b61d9288bde0cbd42))

## [1.20.0](https://github.com/jm33-m0/emp3r0r/compare/v1.19.1...v1.20.0) (2022-09-28)


### Features

* enable tabbed UI, move agentlist to tab ([7417076](https://github.com/jm33-m0/emp3r0r/commit/7417076637f5aa333e754ba1a9fa5a80bfd0e80c))


### Bug Fixes

* confusing tmux error messages ([1edb75b](https://github.com/jm33-m0/emp3r0r/commit/1edb75b3d50bc39392523efbabdfd0c017f78be2))
* killing non-existent processes ([03fdf33](https://github.com/jm33-m0/emp3r0r/commit/03fdf3343b6a15b1492470e4cacb471541f9001f))
* premature downloading from agent side, '.downloading' file not removed ([b4598d5](https://github.com/jm33-m0/emp3r0r/commit/b4598d5efa7c31569dc215d7bde65e109d0321ab))

## [1.19.1](https://github.com/jm33-m0/emp3r0r/compare/v1.19.0...v1.19.1) (2022-09-09)


### Bug Fixes

* sanitize filename ([33f724e](https://github.com/jm33-m0/emp3r0r/commit/33f724eabfa3c879b4cb4f4360716825c3ef2930))

## [1.19.0](https://github.com/jm33-m0/emp3r0r/compare/v1.18.0...v1.19.0) (2022-09-09)


### Features

* fixed [#160](https://github.com/jm33-m0/emp3r0r/issues/160), file server rewritten, allow only connected agents to download files from CC ([cafeb9d](https://github.com/jm33-m0/emp3r0r/commit/cafeb9d5f6690d6b6e41a26899d481d644ae29af))


### Bug Fixes

* use fallback UUID when unable to obtain product serial ([bbbfd73](https://github.com/jm33-m0/emp3r0r/commit/bbbfd739bdc0d1a28935aafd9cd23515776f78fb))

## [1.18.0](https://github.com/jm33-m0/emp3r0r/compare/v1.17.5...v1.18.0) (2022-08-18)


### Features

* bash dropper ([79406ed](https://github.com/jm33-m0/emp3r0r/commit/79406edb35dedeffe69c925fca4825e52de53f6c))

## [1.17.5](https://github.com/jm33-m0/emp3r0r/compare/v1.17.4...v1.17.5) (2022-08-15)


### Bug Fixes

* optimize build script ([3ebbee9](https://github.com/jm33-m0/emp3r0r/commit/3ebbee9b64a3f4b102b3fc303c683396d5011fd0))
* smaller tar archive ([07e6e9e](https://github.com/jm33-m0/emp3r0r/commit/07e6e9e046725d8e5bf876f20df084e2adcef4bf))

## [1.17.4](https://github.com/jm33-m0/emp3r0r/compare/v1.17.3...v1.17.4) (2022-07-16)


### Bug Fixes

* 149 ([04188f7](https://github.com/jm33-m0/emp3r0r/commit/04188f7dc4ecad0d84149b5de92165628c024199))

## [1.17.3](https://github.com/jm33-m0/emp3r0r/compare/v1.17.2...v1.17.3) (2022-06-09)


### Bug Fixes

* race condition in polling ([0caba63](https://github.com/jm33-m0/emp3r0r/commit/0caba63155bbdd6a50d606c67c7bc65268b2395b))

## [1.17.2](https://github.com/jm33-m0/emp3r0r/compare/v1.17.1...v1.17.2) (2022-06-08)


### Bug Fixes

* [#139](https://github.com/jm33-m0/emp3r0r/issues/139) linux cmd exec ([eb73ec5](https://github.com/jm33-m0/emp3r0r/commit/eb73ec53cc8a50cd958963131471ff3c2faa20b6))

## [1.17.1](https://github.com/jm33-m0/emp3r0r/compare/v1.17.0...v1.17.1) (2022-06-08)


### Bug Fixes

* [#139](https://github.com/jm33-m0/emp3r0r/issues/139) ([77c5d3c](https://github.com/jm33-m0/emp3r0r/commit/77c5d3cd3b61d858f6fd044167a166f12dc93b1b))

## [1.17.0](https://github.com/jm33-m0/emp3r0r/compare/v1.16.2...v1.17.0) (2022-06-08)


### Features

* [#163](https://github.com/jm33-m0/emp3r0r/issues/163) support quoted and escaped commands ([dddfd5c](https://github.com/jm33-m0/emp3r0r/commit/dddfd5c518ed0a82ec69afc79576861ff3f85208))

## [1.16.2](https://github.com/jm33-m0/emp3r0r/compare/v1.16.1...v1.16.2) (2022-06-07)


### Bug Fixes

* [#136](https://github.com/jm33-m0/emp3r0r/issues/136) ([f433a7f](https://github.com/jm33-m0/emp3r0r/commit/f433a7f47e948589d46dc6e925dd768c63ef4d81))
* conhost.exe cannot exec commands on Windows 7 ([5107eb7](https://github.com/jm33-m0/emp3r0r/commit/5107eb7776b9f184e4a510060516d42e096907a9))

### [1.16.1](https://github.com/jm33-m0/emp3r0r/compare/v1.16.0...v1.16.1) (2022-05-18)


### Bug Fixes

* race condition in polling ([b3d4a20](https://github.com/jm33-m0/emp3r0r/commit/b3d4a2074d336c81903487c3a57b3446aa62284b))

## [1.16.0](https://github.com/jm33-m0/emp3r0r/compare/v1.15.9...v1.16.0) (2022-05-17)


### Features

* enable logging for shadowsocks server when debug level is set to `3` ([4d79ea9](https://github.com/jm33-m0/emp3r0r/commit/4d79ea9e52b0debdbc7aee6347eb2c4603b3d8b3))

### [1.15.9](https://github.com/jm33-m0/emp3r0r/compare/v1.15.8...v1.15.9) (2022-04-19)


### Bug Fixes

* command pane remains after exiting emp3r0r ([ed3cf1c](https://github.com/jm33-m0/emp3r0r/commit/ed3cf1cec5220bec3f7f9f61f86816323148c356))
* selected agent not visible as it's on top of the list ([48fc9a2](https://github.com/jm33-m0/emp3r0r/commit/48fc9a219eb4b8308e416bc6821079993d00e49e))

### [1.15.8](https://github.com/jm33-m0/emp3r0r/compare/v1.15.7...v1.15.8) (2022-04-11)


### Bug Fixes

* Tmux UI outputs on wrong panes/windows ([b440c60](https://github.com/jm33-m0/emp3r0r/commit/b440c60a16476cdc528f7a44518545ae422d3af2))

### [1.15.7](https://github.com/jm33-m0/emp3r0r/compare/v1.15.6...v1.15.7) (2022-04-11)


### Bug Fixes

* [#122](https://github.com/jm33-m0/emp3r0r/issues/122) title bar height not considered ([98cc556](https://github.com/jm33-m0/emp3r0r/commit/98cc5562c373ce144a3dbf445af7ee0c28567811))

### [1.15.6](https://github.com/jm33-m0/emp3r0r/compare/v1.15.5...v1.15.6) (2022-04-10)


### Bug Fixes

* windows sysinfo ([8c7c080](https://github.com/jm33-m0/emp3r0r/commit/8c7c080235f54f3f6c6e5234fb54084b7d805d3b))

### [1.15.5](https://github.com/jm33-m0/emp3r0r/compare/v1.15.4...v1.15.5) (2022-04-09)


### Bug Fixes

* `interactive_shell` for Windows: fails to find shell process sometimes ([bf1883d](https://github.com/jm33-m0/emp3r0r/commit/bf1883d17bfb133d73870f3d6e7fdcd8c75a24e4))
* `interactive_shell` for Windows: too many callback functions ([1f0155b](https://github.com/jm33-m0/emp3r0r/commit/1f0155b34715bcf6ce04206dc18699d4e04e429e))

### [1.15.4](https://github.com/jm33-m0/emp3r0r/compare/v1.15.3...v1.15.4) (2022-04-08)


### Bug Fixes

* [#122](https://github.com/jm33-m0/emp3r0r/issues/122) window resizing now works mostly ([bb1af5d](https://github.com/jm33-m0/emp3r0r/commit/bb1af5d694c685982190c24bd6b9351c482c62fa))

### [1.15.3](https://github.com/jm33-m0/emp3r0r/compare/v1.15.2...v1.15.3) (2022-04-07)


### Bug Fixes

* [#122](https://github.com/jm33-m0/emp3r0r/issues/122) partially fix, shell window in main tmux pane now works ([17141b8](https://github.com/jm33-m0/emp3r0r/commit/17141b84c46f4986c7baf8fee9213d8478d1f6d0))

### [1.15.2](https://github.com/jm33-m0/emp3r0r/compare/v1.15.1...v1.15.2) (2022-04-06)


### Bug Fixes

* windows `interactive_shell` has visible console windows ([4dfd893](https://github.com/jm33-m0/emp3r0r/commit/4dfd8938645827d6ffdd731ffb1601dadaf6d7f9))

### [1.15.1](https://github.com/jm33-m0/emp3r0r/compare/v1.15.0...v1.15.1) (2022-04-06)


### Bug Fixes

* [#94](https://github.com/jm33-m0/emp3r0r/issues/94) windows support now complete ([d7b812d](https://github.com/jm33-m0/emp3r0r/commit/d7b812df0a5a77aec24c58df99f6b3bf925c8b2b))

## [1.15.0](https://github.com/jm33-m0/emp3r0r/compare/v1.14.7...v1.15.0) (2022-04-04)


### Features

* remove agent on command exec timeout ([97eacdb](https://github.com/jm33-m0/emp3r0r/commit/97eacdbf7841b314062fbcb6148463b1018ff1bd))

### [1.14.7](https://github.com/jm33-m0/emp3r0r/compare/v1.14.6...v1.14.7) (2022-04-02)


### Bug Fixes

* [#118](https://github.com/jm33-m0/emp3r0r/issues/118) implement a 2min timeout in C&C tun ([2ecccf6](https://github.com/jm33-m0/emp3r0r/commit/2ecccf60db1966fe83e8c5006618da02b4b20356))

### [1.14.6](https://github.com/jm33-m0/emp3r0r/compare/v1.14.5...v1.14.6) (2022-04-02)


### Bug Fixes

* `cc_indicator` option not covered by `gen_agent` ([374ad67](https://github.com/jm33-m0/emp3r0r/commit/374ad67677d0d50fb368754e0513d11916c944b4))
* logging level in checkinHandler ([ea06c68](https://github.com/jm33-m0/emp3r0r/commit/ea06c68084b803b2a0ae7caa444df321d93d5361))

### [1.14.5](https://github.com/jm33-m0/emp3r0r/compare/v1.14.4...v1.14.5) (2022-04-01)


### Bug Fixes

* address [#45](https://github.com/jm33-m0/emp3r0r/issues/45), do not start socks5 proxy unless told to ([e9deb8e](https://github.com/jm33-m0/emp3r0r/commit/e9deb8e402dbc5147b3d89eda8d31333d65d5756))

### [1.14.4](https://github.com/jm33-m0/emp3r0r/compare/v1.14.3...v1.14.4) (2022-04-01)


### Bug Fixes

* `garble -tiny build` in build script ([b643875](https://github.com/jm33-m0/emp3r0r/commit/b6438756aa6a7433b703c787593504661b6b8175))

### [1.14.3](https://github.com/jm33-m0/emp3r0r/compare/v1.14.2...v1.14.3) (2022-04-01)


### Bug Fixes

* vaccine fails to configure on agent start ([c74e7fb](https://github.com/jm33-m0/emp3r0r/commit/c74e7fb8611f767807a8fde3a2fa73fced741c12))

### [1.14.2](https://github.com/jm33-m0/emp3r0r/compare/v1.14.1...v1.14.2) (2022-04-01)


### Bug Fixes

* `emp3r0r --release` cannot build agent stub ([a277515](https://github.com/jm33-m0/emp3r0r/commit/a277515557c8c1fab3ecd7a971cff71a1981bf1d))

### [1.14.1](https://github.com/jm33-m0/emp3r0r/compare/v1.14.0...v1.14.1) (2022-04-01)


### Bug Fixes

* agent not reconnecting immediately after losing connection ([59eaa1f](https://github.com/jm33-m0/emp3r0r/commit/59eaa1ff6b64f4d07fc84db31a468276ba833102))
* ConnectCC stucks when using KCP ([58d5f89](https://github.com/jm33-m0/emp3r0r/commit/58d5f89aa0506c95f1d29824046979ab2026393b))
* ConnectCC timeout not implemented correctly ([d58ac5e](https://github.com/jm33-m0/emp3r0r/commit/d58ac5eaed680ab591091f920a39d801cba1b090))
* KCPClient crash ([f5202ef](https://github.com/jm33-m0/emp3r0r/commit/f5202ef5c6d70279c096cf4a5be55af12c9f2782))
* KCPClient not aware of C2 disconnection ([58a63a2](https://github.com/jm33-m0/emp3r0r/commit/58a63a22d70877f3aee0ea71b49e502db2245257))
* timeout TLS handshake, do not wait infinitely ([24dd54f](https://github.com/jm33-m0/emp3r0r/commit/24dd54f96a7c83f8439394eb35314154dc2ce0e3))

## [1.14.0](https://github.com/jm33-m0/emp3r0r/compare/v1.13.0...v1.14.0) (2022-03-31)


### Features

* add verification to handshake process ([6a9fc04](https://github.com/jm33-m0/emp3r0r/commit/6a9fc0404c562c547e6676e95e2d8ec5a483279b))

## [1.13.0](https://github.com/jm33-m0/emp3r0r/compare/v1.12.0...v1.13.0) (2022-03-31)


### Features

* add KCP C2 transport ([d33c9a1](https://github.com/jm33-m0/emp3r0r/commit/d33c9a102424067f90eee6a9fb79972df3c0ef71))
* add KCP transport, C2 traffic in obfuscated and fast UDP ([024543e](https://github.com/jm33-m0/emp3r0r/commit/024543efd03884343560c475990ad07f5743d208))

## [1.12.0](https://github.com/jm33-m0/emp3r0r/compare/v1.11.0...v1.12.0) (2022-03-30)


### Features

* randomize heartbeat payload length ([920d01d](https://github.com/jm33-m0/emp3r0r/commit/920d01dfe3fbb77edf8245c4b8d88624178b8d52))
* reduce and randomize C2 heart-beat traffic, may cause longer wait time in agent state checking ([dee4b30](https://github.com/jm33-m0/emp3r0r/commit/dee4b30e4bd696b46c044386d219040715ad35ad))


### Bug Fixes

* agent does not connect immediately after checking in ([afa4bff](https://github.com/jm33-m0/emp3r0r/commit/afa4bff4b54807a991c6d364b1384a6d6cdf54bf))
* agent re-connection takes too long ([4febec6](https://github.com/jm33-m0/emp3r0r/commit/4febec6c7add168919f957cb7808df7c04ac2f10))
* alert user only when the agent is connected correctly ([44ee708](https://github.com/jm33-m0/emp3r0r/commit/44ee7086340d4c8d36d0be2b6ec28bcfb3bbb705))
* line wrapping in `CliPrettyPrint` ([f406224](https://github.com/jm33-m0/emp3r0r/commit/f4062247518cda72642b65558743d03d08eac395))
* line wrapping in agent list brings extra whitespaces ([3a03153](https://github.com/jm33-m0/emp3r0r/commit/3a03153c5f05fda718392661ae30f6c79335f6c5))
* line wrapping inside tables ([5f6b3db](https://github.com/jm33-m0/emp3r0r/commit/5f6b3db264dcfb93237504c35578049c0db33d81))
* RandStr not random enough with time.Now as seed ([e3aed62](https://github.com/jm33-m0/emp3r0r/commit/e3aed626744c55b0488a4035ce256aa17f48e6a2))
* some values in emp3r0r.json are not updated ([70c0f5e](https://github.com/jm33-m0/emp3r0r/commit/70c0f5ec7c6b0dd458b6cbdfeb4489904925bd10))

## [1.11.0](https://github.com/jm33-m0/emp3r0r/compare/v1.10.7...v1.11.0) (2022-03-29)


### Features

* add shadowsocks ([a8117e9](https://github.com/jm33-m0/emp3r0r/commit/a8117e97a6c818b9c548bc474027cc47dd24b708))
* Add Shadowsocks obfuscator to C2 transport ([73a4d67](https://github.com/jm33-m0/emp3r0r/commit/73a4d6782712388e3ee76b9babcfa3b6dc314f30))
* use upx to further compress packed agent binaries ([1c6800f](https://github.com/jm33-m0/emp3r0r/commit/1c6800ff4a3162c8e64f72f28b78f2582f0e2db7))


### Bug Fixes

* `garble -tiny` now works ([3c1b9b3](https://github.com/jm33-m0/emp3r0r/commit/3c1b9b32e1fa4476f7ed6a047689f3c47482879b))

### [1.10.7](https://github.com/jm33-m0/emp3r0r/compare/v1.10.6...v1.10.7) (2022-03-28)


### Bug Fixes

* empty envv when started from memfd_exec ([f6a6b7d](https://github.com/jm33-m0/emp3r0r/commit/f6a6b7dfea7f4e09f2b6f136d018c0fe97529072))
* packer: pass config data and ELF through envv ([b6a0d7b](https://github.com/jm33-m0/emp3r0r/commit/b6a0d7b4d831497e66d46b5d36071e46fb2b6e06))

### [1.10.6](https://github.com/jm33-m0/emp3r0r/compare/v1.10.5...v1.10.6) (2022-03-27)


### Bug Fixes

* [#105](https://github.com/jm33-m0/emp3r0r/issues/105) ([32d88f7](https://github.com/jm33-m0/emp3r0r/commit/32d88f72b7b400959e41031414370baa0beba42e))
* [#105](https://github.com/jm33-m0/emp3r0r/issues/105), show C2 names in cowsay ([d76e7cb](https://github.com/jm33-m0/emp3r0r/commit/d76e7cb6c33de6c4cda989ec516ac2dde919aac5))

### [1.10.5](https://github.com/jm33-m0/emp3r0r/compare/v1.10.4...v1.10.5) (2022-03-26)


### Bug Fixes

* PKGBUILD for blackarch ([e496738](https://github.com/jm33-m0/emp3r0r/commit/e4967387f66bfd605b97a8c231631a2abc95506f))

### [1.10.4](https://github.com/jm33-m0/emp3r0r/compare/v1.10.3...v1.10.4) (2022-03-25)


### Bug Fixes

* unable to execute cat since `PATH` is not set ([5049837](https://github.com/jm33-m0/emp3r0r/commit/5049837726f009891137364cbabec3533359f7bd))

### [1.10.3](https://github.com/jm33-m0/emp3r0r/compare/v1.10.2...v1.10.3) (2022-03-25)


### Bug Fixes

* filename autocompletion for packer ([1a9d180](https://github.com/jm33-m0/emp3r0r/commit/1a9d180e95b83a52d3007880b0d987803b9208be))
* make packed binaries executable by default ([5d2c944](https://github.com/jm33-m0/emp3r0r/commit/5d2c9448adea5b8f684b8e80cc601f6f962f6b91))
* packed agent cannot find config data ([e621808](https://github.com/jm33-m0/emp3r0r/commit/e621808bed15ea0ec4189e5c31240b9f31034a4f))
* packer blocks UI ([6788b35](https://github.com/jm33-m0/emp3r0r/commit/6788b351cae09dd90f6fbe14e9ef6a9cbb27ac66))
* reduce packer_stub binary size ([c67fff9](https://github.com/jm33-m0/emp3r0r/commit/c67fff9632d2d4f6c9647828731e1e782730dd14))
* reduce size of data package ([c441325](https://github.com/jm33-m0/emp3r0r/commit/c441325aa23f7b166b2419049163af59a653e83f))
* unable to extract config data when agent is packed ([c8b5198](https://github.com/jm33-m0/emp3r0r/commit/c8b5198553357ba5fd8c35d159231d0e17fbbee6))
* unable to extract data from file/mem ([eff9574](https://github.com/jm33-m0/emp3r0r/commit/eff9574417883ec6c8b5820bb0b199acea7806bd))
* unable to extract embeded json config ([1c80ec8](https://github.com/jm33-m0/emp3r0r/commit/1c80ec869f6dc24fa692d89422c04ac746e970f2))

### [1.10.2](https://github.com/jm33-m0/emp3r0r/compare/v1.10.1...v1.10.2) (2022-03-25)


### Bug Fixes

* `emp3r0r --release` fails to build packer_stub ([5dd8f99](https://github.com/jm33-m0/emp3r0r/commit/5dd8f997e249abd84b7128760731ae72e0f42131))

### [1.10.1](https://github.com/jm33-m0/emp3r0r/compare/v1.10.0...v1.10.1) (2022-03-24)


### Bug Fixes

* packer_stub.exe path ([7b7a2d7](https://github.com/jm33-m0/emp3r0r/commit/7b7a2d7b49d86dec2948d3de18c66ff918c30c49))

## [1.10.0](https://github.com/jm33-m0/emp3r0r/compare/v1.9.0...v1.10.0) (2022-03-24)


### Features

* check if agent is started by ELF loader by PATH hash ([2df3c1d](https://github.com/jm33-m0/emp3r0r/commit/2df3c1d827f5634bc25f2ae9f116bfdfa99e88a4))
* integrate packer into C2 ([c81cd7d](https://github.com/jm33-m0/emp3r0r/commit/c81cd7dd1e69042fb2fe78964eae3c4884ae6542))


### Bug Fixes

* pack_agent command ([7d2dcea](https://github.com/jm33-m0/emp3r0r/commit/7d2dcea321695a52256416a1f29e7fd672953fe4))

## [1.9.0](https://github.com/jm33-m0/emp3r0r/compare/v1.8.1...v1.9.0) (2022-03-23)


### Features

* emp3r0r installer ([f126780](https://github.com/jm33-m0/emp3r0r/commit/f12678038a53e12862865b17048e2e7ba69b4ba0))
* install emp3r0r to your system, load custom modules from ~/.emp3r0r ([77f1564](https://github.com/jm33-m0/emp3r0r/commit/77f1564d9dd556271efb726272278121ad3cd747))
* use colored print for all fatal errors ([9933d86](https://github.com/jm33-m0/emp3r0r/commit/9933d8635318757ca8d4e477fc3ea66cc013ec8b))


### Bug Fixes

* cannot pack custom modules due to incorrect path ([c535350](https://github.com/jm33-m0/emp3r0r/commit/c535350a52f4d6906d8fe1473398636ccd983fd1))
* emp3r0r launcher/installer path error ([e4e7a91](https://github.com/jm33-m0/emp3r0r/commit/e4e7a91e931ede594aaaaac8320b189546b8ac2d))
* gen_agent: binaries not found ([31b68d1](https://github.com/jm33-m0/emp3r0r/commit/31b68d13fd0e7d620d920ff46a466692462f6f01))
* modules don't load ([7bac146](https://github.com/jm33-m0/emp3r0r/commit/7bac14606a9a4df253d210ab29a30c35bde5257c))
* path errors ([70d8362](https://github.com/jm33-m0/emp3r0r/commit/70d8362fd688d6ab629deac201578c8d27a034e7))
* set correct location for tmux scripts ([a58c1a3](https://github.com/jm33-m0/emp3r0r/commit/a58c1a3381d905ecf260f1b29f2705e4c2f5b8f2))

### [1.8.1](https://github.com/jm33-m0/emp3r0r/compare/v1.8.0...v1.8.1) (2022-03-22)


### Bug Fixes

* 'unknown_host' in agent tag ([1aa8eb4](https://github.com/jm33-m0/emp3r0r/commit/1aa8eb47aa01f0a9a6322d82318e8fb4fd64fec2))
* no build option for Windows ([9c7d22d](https://github.com/jm33-m0/emp3r0r/commit/9c7d22deea7525e7dd888692716c7495a5c5486b))
* reduce agent binary size for windows version ([9a486f7](https://github.com/jm33-m0/emp3r0r/commit/9a486f7bf9a0a2647709ee36f7bba8cc5a5939d4))

## [1.8.0](https://github.com/jm33-m0/emp3r0r/compare/v1.7.6...v1.8.0) (2022-03-22)


### Features

* Add cross-platform support ([666051d](https://github.com/jm33-m0/emp3r0r/commit/666051dca08804b25ecdd217a003aa72890b8871))
* recognize more linux distros, and get vendor name ([5f4df0d](https://github.com/jm33-m0/emp3r0r/commit/5f4df0d3c5771bd902edac316150060e92d23236))


### Bug Fixes

* remove binary from source tree ([c5955b8](https://github.com/jm33-m0/emp3r0r/commit/c5955b8b89d01c2609028c1f4464d778661adbd9))

### [1.7.6](https://github.com/jm33-m0/emp3r0r/compare/v1.7.5...v1.7.6) (2022-03-20)


### Bug Fixes

* ssh shell fails to start due to 'already bind' error ([18004a9](https://github.com/jm33-m0/emp3r0r/commit/18004a9e4641516d3941cde336eb8e970b9bba15))
* unable to config time intervals ([b242e80](https://github.com/jm33-m0/emp3r0r/commit/b242e80582d1052c663c9e37fe41b6efbbd983e9))

### [1.7.5](https://github.com/jm33-m0/emp3r0r/compare/v1.7.4...v1.7.5) (2022-03-20)


### Bug Fixes

* [#89](https://github.com/jm33-m0/emp3r0r/issues/89) ([1e1b838](https://github.com/jm33-m0/emp3r0r/commit/1e1b8380c89effbbdf7d5686147b6666dd1eddfc))

### [1.7.4](https://github.com/jm33-m0/emp3r0r/compare/v1.7.3...v1.7.4) (2022-03-20)


### Bug Fixes

* abort when CA is not added ([3edca43](https://github.com/jm33-m0/emp3r0r/commit/3edca43d8d18765dec794f5e5d4368475963d4fd))
* CA cert missing ([b1885b9](https://github.com/jm33-m0/emp3r0r/commit/b1885b9e81a40fe3072caf15ddd17fb59da35547))

### [1.7.3](https://github.com/jm33-m0/emp3r0r/compare/v1.7.2...v1.7.3) (2022-03-20)


### Bug Fixes

* disable CGO to build static binaries ([f12190f](https://github.com/jm33-m0/emp3r0r/commit/f12190f31ab4791f2029a05b9de6c6075c730fdd))

### [1.7.2](https://github.com/jm33-m0/emp3r0r/compare/v1.7.1...v1.7.2) (2022-03-20)


### Bug Fixes

* binaries not added in archive ([7383bd7](https://github.com/jm33-m0/emp3r0r/commit/7383bd71b5f82606f58ccbe476335b4f66ebe9cd))

### [1.7.1](https://github.com/jm33-m0/emp3r0r/compare/v1.7.0...v1.7.1) (2022-03-20)


### Bug Fixes

* build script typo, archive structure ([ced5651](https://github.com/jm33-m0/emp3r0r/commit/ced56510e4bd82e94894f276c247b345a07150ce))

## [1.7.0](https://github.com/jm33-m0/emp3r0r/compare/v1.6.13...v1.7.0) (2022-03-20)


### Features

* improved C2 launcher, auto-build working ([b33aa19](https://github.com/jm33-m0/emp3r0r/commit/b33aa19a05b74ee8a43980ea741c3d953f98cfa0))

### [1.6.13](https://github.com/jm33-m0/emp3r0r/compare/v1.6.12...v1.6.13) (2022-03-20)


### Bug Fixes

* upload.sh ([ad2315b](https://github.com/jm33-m0/emp3r0r/commit/ad2315b4efd58a50aa8a43cf0df8c25946f4612d))

### [1.6.12](https://github.com/jm33-m0/emp3r0r/compare/v1.6.11...v1.6.12) (2022-03-20)


### Bug Fixes

* test a new release ([6632334](https://github.com/jm33-m0/emp3r0r/commit/66323346228113ae991dbe39731e380b0a6e96be))

### [1.6.11](https://github.com/jm33-m0/emp3r0r/compare/v1.6.10...v1.6.11) (2022-03-20)


### Bug Fixes

* save some time if release not created ([2dc20ef](https://github.com/jm33-m0/emp3r0r/commit/2dc20ef0107b64d6c718d9421771cad96a5212cd))

### [1.6.10](https://github.com/jm33-m0/emp3r0r/compare/v1.6.9...v1.6.10) (2022-03-20)


### Bug Fixes

* curl cmd in workflow file ([db91dd2](https://github.com/jm33-m0/emp3r0r/commit/db91dd272657a35ccda0f53268f188f60d8e80da))

### [1.6.9](https://github.com/jm33-m0/emp3r0r/compare/v1.6.8...v1.6.9) (2022-03-20)


### Bug Fixes

* curl upload asset ([058a637](https://github.com/jm33-m0/emp3r0r/commit/058a6370aa9a28374342dd9d7c7e0c9de80c2cb4))

### [1.6.8](https://github.com/jm33-m0/emp3r0r/compare/v1.6.7...v1.6.8) (2022-03-20)


### Bug Fixes

* upload assets: not found ([2d87428](https://github.com/jm33-m0/emp3r0r/commit/2d87428f333716c01c20988add41c52dca0d573f))

### [1.6.7](https://github.com/jm33-m0/emp3r0r/compare/v1.6.6...v1.6.7) (2022-03-20)


### Bug Fixes

* upload assets ([c9fb994](https://github.com/jm33-m0/emp3r0r/commit/c9fb994b6aa995cab0f3e28f988d6efefb824ba1))

### [1.6.6](https://github.com/jm33-m0/emp3r0r/compare/v1.6.5...v1.6.6) (2022-03-20)


### Bug Fixes

* workflow steps ([3a3b0bd](https://github.com/jm33-m0/emp3r0r/commit/3a3b0bdbc3b33efadc3a726a5422370a79edc81a))

### [1.6.5](https://github.com/jm33-m0/emp3r0r/compare/v1.6.4...v1.6.5) (2022-03-20)


### Bug Fixes

* upload-asset: file not found ([a3a6c10](https://github.com/jm33-m0/emp3r0r/commit/a3a6c10d6a90dd00c376b60fccd243ab9ed4aecc))

### [1.6.4](https://github.com/jm33-m0/emp3r0r/compare/v1.6.3...v1.6.4) (2022-03-20)


### Bug Fixes

* trying to upload assets ([8fb049d](https://github.com/jm33-m0/emp3r0r/commit/8fb049d51ba8e25a62cee13a7acdeeffee2e73e5))

### [1.6.2](https://github.com/jm33-m0/emp3r0r/compare/v1.6.1...v1.6.2) (2022-03-20)


### Bug Fixes

* need to check out repo before creating release archive ([dc3947b](https://github.com/jm33-m0/emp3r0r/commit/dc3947bd70103ca726ce801cb7007bb352cb1f90))

### [1.6.1](https://github.com/jm33-m0/emp3r0r/compare/v1.6.0...v1.6.1) (2022-03-20)


### Bug Fixes

* update go dependencies ([018b533](https://github.com/jm33-m0/emp3r0r/commit/018b533e55d6bfd15a2e28ca85a144adea87d42f))

## [1.6.0](https://github.com/jm33-m0/emp3r0r/compare/v1.5.1...v1.6.0) (2022-03-18)


### Features

* implement build.py in CC ([4d237b0](https://github.com/jm33-m0/emp3r0r/commit/4d237b058c37ec97c390530609bf5c55642b0a07))


### Bug Fixes

* build --clean success message ([6eebb2b](https://github.com/jm33-m0/emp3r0r/commit/6eebb2b78d84cd7632fca6a120eceb7979b112ac))
* build.py --target clean deletes everything ([6842acc](https://github.com/jm33-m0/emp3r0r/commit/6842accd8cc7ab9e9324243b0f98e8c042ac0483))
* ca key file name ([5547eed](https://github.com/jm33-m0/emp3r0r/commit/5547eeddf1f326242e4483c1a632acf831eb5b79))
* CliAsk: ignore ctrl-c and EOF ([85180af](https://github.com/jm33-m0/emp3r0r/commit/85180af56a61b8706eee8f0f7612572f0393051b))
* disallow empty input ([2c3c76d](https://github.com/jm33-m0/emp3r0r/commit/2c3c76da6bd711de28cd1defb890cd444492a536))
* emp3r0r.json initialization not complete ([6369379](https://github.com/jm33-m0/emp3r0r/commit/6369379271a15f014a5bb6481a4020a54d86293b))
* init emp3r0r.json when it's not found ([1aed32c](https://github.com/jm33-m0/emp3r0r/commit/1aed32c897f0783c2c878b6f28112a8cbd860458))
* toggle some config options on/off ([abe600f](https://github.com/jm33-m0/emp3r0r/commit/abe600f0079bfa884c8f73a2585340679daacf96))

### [1.5.1](https://github.com/jm33-m0/emp3r0r/compare/v1.5.0...v1.5.1) (2022-03-17)


### Bug Fixes

* gen_agent: build stub.exe first ([ae01a32](https://github.com/jm33-m0/emp3r0r/commit/ae01a322bb5e0e40a8b8af9aa31e9964903f6b9e))

## [1.5.0](https://github.com/jm33-m0/emp3r0r/compare/v1.4.1...v1.5.0) (2022-03-17)


### Features

* build system redesigned ([38cfd9f](https://github.com/jm33-m0/emp3r0r/commit/38cfd9ff7c26a87773b72b0e3a6e1615177520d6))
* build.py now generates stub.exe ([3dd2009](https://github.com/jm33-m0/emp3r0r/commit/3dd2009bd8cb2e9d4eb5fda056e65883b9aede22))
* change build process ([a5fc6eb](https://github.com/jm33-m0/emp3r0r/commit/a5fc6ebdd39b846eaefcb4172baff2fc202241ae))
* cmd handler is blocking most commands ([c500a6e](https://github.com/jm33-m0/emp3r0r/commit/c500a6efbd1feaec5c9441dd498db24d32c07584))
* do not pack agent binaries ([d65e675](https://github.com/jm33-m0/emp3r0r/commit/d65e675d226226c497bc8c6b367a034b6332348c))
* generate agent id from host config ([1bf31c2](https://github.com/jm33-m0/emp3r0r/commit/1bf31c2c65e26caf1242ebaf76f2b52eaf3e6e47))
* remove windows support ([3a9660e](https://github.com/jm33-m0/emp3r0r/commit/3a9660e72870c594cf1390c9e7513fa749de00ba))
* rename outfile ([5512998](https://github.com/jm33-m0/emp3r0r/commit/55129983ed5f56137d5d6bf5eed2bb2b0be9844e))


### Bug Fixes

* emp3r0r.json: socket name ([f6c42a9](https://github.com/jm33-m0/emp3r0r/commit/f6c42a99236e0c69a632e69f8b94c328bc39f345))
* file paths ([284f161](https://github.com/jm33-m0/emp3r0r/commit/284f161cafe374c1c1d6ec79a287c2b9da30e733))
* gen_agent command ([3121a59](https://github.com/jm33-m0/emp3r0r/commit/3121a59862d8b16824b2229be1392449f9c56dbe))
* magic string should be pre-set ([9dd87a9](https://github.com/jm33-m0/emp3r0r/commit/9dd87a9f3febd0f11f86aa23102df62404e6f2b7))
* no need to decompress ([eb231e9](https://github.com/jm33-m0/emp3r0r/commit/eb231e9ef30a3f55bf0bb2994df755aff7c838f7))
* python path ([a437008](https://github.com/jm33-m0/emp3r0r/commit/a437008c6e67ffdda15c20bb719420c77502358c))
* rm redundant build function ([cbaa7e7](https://github.com/jm33-m0/emp3r0r/commit/cbaa7e7a3226102ae359b012f4d2f8898ea48425))
* should rm python archive ([68deedd](https://github.com/jm33-m0/emp3r0r/commit/68deedd61f9ee6ca83af8cdf1401a5a91ec85793))
* tmux cat ([8d8a3c8](https://github.com/jm33-m0/emp3r0r/commit/8d8a3c818137aa95190910b366c96d72235e4fe3))
* update build.py to match build dir change ([0142126](https://github.com/jm33-m0/emp3r0r/commit/014212692f127d9c26dda6d73ff32d1fbdfb75ba))
* update c2 launcher ([406b1bf](https://github.com/jm33-m0/emp3r0r/commit/406b1bf4a7d7be7dcafe4b37004601656be62bd0))
* update launcher ([22b4078](https://github.com/jm33-m0/emp3r0r/commit/22b4078ce933ef965a1dad45c9434c03264e2492))
* utils_path and socket name should follow agent_root ([fe514b7](https://github.com/jm33-m0/emp3r0r/commit/fe514b71bdff9cc6aa30b4a06f476b43f968dfd3))

### [1.4.1](https://github.com/jm33-m0/emp3r0r/compare/v1.4.0...v1.4.1) (2022-03-16)


### Bug Fixes

* onion address checking ([628d527](https://github.com/jm33-m0/emp3r0r/commit/628d5275d59e2adee687c8d48ed85ec15ca24c95))
* print 'go build ends' after `go build` ([a73ff81](https://github.com/jm33-m0/emp3r0r/commit/a73ff8165d24227cf633910e4b7857614a3ee7a6))
* restore source files when build is aborted ([07ab26c](https://github.com/jm33-m0/emp3r0r/commit/07ab26c86d03e64f9ab1fa08d23d0c13a19671fd))

## [1.4.0](https://github.com/jm33-m0/emp3r0r/compare/v1.3.20...v1.4.0) (2022-03-16)


### Features

* add cowsay ([74be24c](https://github.com/jm33-m0/emp3r0r/commit/74be24c25af23814df0ccbe2b35f81480cc8d18d))


### Bug Fixes

* C2 prints the wrong version string ([a59e18c](https://github.com/jm33-m0/emp3r0r/commit/a59e18c2abef429d98bd886d325023c972c069e2))
* LD_LIBRARY_PATH was mistakenly unset ([0cd3f3e](https://github.com/jm33-m0/emp3r0r/commit/0cd3f3ecb2f0959563151fe4d51e6556d3e222ef))
* missing file in dockerscan libs ([7a49ed7](https://github.com/jm33-m0/emp3r0r/commit/7a49ed7a7a9b6706e06252f63b5c4abc2a439b9d))

### [1.3.20](https://github.com/jm33-m0/emp3r0r/compare/v1.3.19...v1.3.20) (2022-03-15)


### Bug Fixes

* clear changlog ([88b425a](https://github.com/jm33-m0/emp3r0r/commit/88b425a69240d708cf6458141a1c0cb52ee565d8))
