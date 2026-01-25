# Changelog

## [3.14.0](https://github.com/jm33-m0/emp3r0r/compare/v3.13.2...v3.14.0) (2026-01-25)


### Features

* Implement in-memory ELF execution with PTY support and streamline agent operations by removing dedicated agent root, PID file, and socket-based liveness checks. ([c528a94](https://github.com/jm33-m0/emp3r0r/commit/c528a94330a633a5738b13218956d171ef653340))


### Bug Fixes

* add retry logic to config download and WireGuard file server startup, alongside a new test for config download retries. ([2776b2e](https://github.com/jm33-m0/emp3r0r/commit/2776b2e8f6e7c22e42087e9c306f2ac4ee1d5a53))
* auto-completion for memory backed file system ([35455fd](https://github.com/jm33-m0/emp3r0r/commit/35455fd6a208e88c593e7577448d21c15be6c3db))
* clean up bettercap, elvish, and go_lpe modules along with the go-winio dependency. ([4f9fab5](https://github.com/jm33-m0/emp3r0r/commit/4f9fab5591dd0a175fb94f56b34db22616305bef))
* Implement agent-side file decryption command and refine `mem://` path descriptions for clarity. ([345ea1c](https://github.com/jm33-m0/emp3r0r/commit/345ea1c7dc4c5e13fa3c39cca700c901c7496b6e))
* introduce `netutil.JoinURL` for robust and consistent URL construction throughout the agent. ([38404ae](https://github.com/jm33-m0/emp3r0r/commit/38404ae5cca9892845018e43d778dee8d4b405a7))
* refactor memory-backed file system with `mem://` prefix for agent file storage and operations. ([72d5026](https://github.com/jm33-m0/emp3r0r/commit/72d5026ba213f03cc823d31ff10bde24f218fc1d))
* simplify agent logging ([80d2f3c](https://github.com/jm33-m0/emp3r0r/commit/80d2f3cddf4d79b6f7d2ad58db8f5746718d1ae3))
* simplify module handling by enforcing in-memory execution and removing on-disk support. ([6494d33](https://github.com/jm33-m0/emp3r0r/commit/6494d33a7638e1670ad052af84f8939f48b8355a))
* use the current process name for in-memory ELF execution. ([e41d0aa](https://github.com/jm33-m0/emp3r0r/commit/e41d0aa84e02c4c08218bc763c84fa1a1ee58169))

## [3.13.2](https://github.com/jm33-m0/emp3r0r/compare/v3.13.1...v3.13.2) (2026-01-20)


### Bug Fixes

* Improve path sanitization in `SecureLocalPath` to correctly handle Windows paths and apply robust path processing to file transfers. ([3c0c0ca](https://github.com/jm33-m0/emp3r0r/commit/3c0c0ca0beb0394fb4478402ec7d62e0434a11fd))

## [3.13.1](https://github.com/jm33-m0/emp3r0r/compare/v3.13.0...v3.13.1) (2026-01-20)


### Bug Fixes

* sanitize path names in archive extraction and P2P file serving. ([a793882](https://github.com/jm33-m0/emp3r0r/commit/a7938824d9ba4d270594b7e38d7b3a3fa8db9868))

## [3.13.0](https://github.com/jm33-m0/emp3r0r/compare/v3.12.0...v3.13.0) (2026-01-20)


### Features

* add memory-backed file storage and configurable storage strategies for agent files, including C2 commands and tests. ([34d8aeb](https://github.com/jm33-m0/emp3r0r/commit/34d8aeb9a96164c6b09b34588bb892174463241c))
* implement in-memory file storage with unified encryption, dynamic sizing, and special handling for executables. ([9e48a52](https://github.com/jm33-m0/emp3r0r/commit/9e48a528942ede40f2a296f564edea6810ab270c))
* implement transparent file encryption for agent-side file operations. ([c258a4a](https://github.com/jm33-m0/emp3r0r/commit/c258a4a42517f7a180385ff2dc94a81fd46c900e))


### Bug Fixes

* implement agent UUID signature verification during check-in and message tunnel hello. ([c8d0db2](https://github.com/jm33-m0/emp3r0r/commit/c8d0db249085dab746579e7f749b4072a669aa67))
* improve RandInt security by using crypto/rand.Int with math/big. ([a60eed0](https://github.com/jm33-m0/emp3r0r/commit/a60eed0706026effcdc1b9d3bc47b3e20de9c46b))
* introduce `!sysinfo` command for comprehensive system details and optimize agent startup with minimal info collection. ([b0e0d6c](https://github.com/jm33-m0/emp3r0r/commit/b0e0d6c74738da694a9c16d5fdcbbf9d0e6665e8))
* relocate Shadowsocks server initialization to the proxychain module. only run it on demand. ([bd99fc1](https://github.com/jm33-m0/emp3r0r/commit/bd99fc1bd0b45af9efebb89e2e944a5b970cbfe6))
* remove injector, persistence, vaccine modules. BOF modules planned. ([58d6a1e](https://github.com/jm33-m0/emp3r0r/commit/58d6a1e841fe1f4592e5a4b6c7f216ac29799c73))
* remove noisy agent upgrade command and its associated functionality. ([d889590](https://github.com/jm33-m0/emp3r0r/commit/d889590e9326c6fd6bc279cc32aeae5e1145bfe1))
* remove vaccine, injector, and persistence modules along with their associated files and configurations. ([61d8b34](https://github.com/jm33-m0/emp3r0r/commit/61d8b34311ab4763eaa94ea3768826e12e6ffd26))

## [3.12.0](https://github.com/jm33-m0/emp3r0r/compare/v3.11.1...v3.12.0) (2026-01-18)


### Features

* add Linux BOF loader support with tests and argument handling ([01e76ab](https://github.com/jm33-m0/emp3r0r/commit/01e76abfccc486546a213dbb34a6dbd7839a89ce))

## [3.11.1](https://github.com/jm33-m0/emp3r0r/compare/v3.11.0...v3.11.1) (2026-01-12)


### Bug Fixes

* replace HandShakes map with sync.Map for concurrent access ([5661133](https://github.com/jm33-m0/emp3r0r/commit/56611331072d4fb584c0009d01d63e589f0c3f0e))

## [3.11.0](https://github.com/jm33-m0/emp3r0r/compare/v3.10.3...v3.11.0) (2026-01-12)


### Features

* add `process_list_handles` COFF module for testing ([538eca8](https://github.com/jm33-m0/emp3r0r/commit/538eca89af26fa16edf8d4b6763e7ac0f83caec9))
* add COFF module support ([1524961](https://github.com/jm33-m0/emp3r0r/commit/1524961f115ed39233c83a84e337adf19d061a51))
* refactor module configuration and invocation handling ([55277dc](https://github.com/jm33-m0/emp3r0r/commit/55277dc5e84c92258b81d3cec3df4ef43ce95afa))


### Bug Fixes

* enhance COFF value normalization to support additional integer types and improve test coverage ([22ca47b](https://github.com/jm33-m0/emp3r0r/commit/22ca47b646941cd7a8a997aac27bb984dbb8ae52))
* handle panic in `runCOFFModule` to improve stability ([0e6f368](https://github.com/jm33-m0/emp3r0r/commit/0e6f3688159893124ab7421fca23325c80f088f0))
* improve agent config extraction logic to handle raw bytes and legacy padded blobs ([26ab5e6](https://github.com/jm33-m0/emp3r0r/commit/26ab5e64475a9cb9e31ae5826ce5166fc0ab7466))
* optimize hello message acknowledgment logic in MsgTunneler ([c069335](https://github.com/jm33-m0/emp3r0r/commit/c0693357279073631d8e5f8a690d065f8d4da586))
* update COFF value normalization to include prefixes for types ([576b625](https://github.com/jm33-m0/emp3r0r/commit/576b62548014a5c4711a005f3587a26603e09a5b))
* update Windows build support with conditional GUI flag so `debug` mode can work ([58aa91c](https://github.com/jm33-m0/emp3r0r/commit/58aa91c8ceb02fa27148b65a8857662b33418322))

## [3.10.3](https://github.com/jm33-m0/emp3r0r/compare/v3.10.2...v3.10.3) (2026-01-05)


### Bug Fixes

* bump version ([d66b9c8](https://github.com/jm33-m0/emp3r0r/commit/d66b9c89d8a4394531d041d9d005ee1ee39e0b5d))

## [3.10.2](https://github.com/jm33-m0/emp3r0r/compare/v3.10.1...v3.10.2) (2026-01-04)


### Bug Fixes

* **config:** enhance CCAddress handling for Tor and KCP configurations, add comprehensive tests ([723a2c2](https://github.com/jm33-m0/emp3r0r/commit/723a2c20c782c1cbce0a5a29da287e392154ef5b))
* **config:** implement default values for missing critical fields and add tests for config flow ([c8ebd85](https://github.com/jm33-m0/emp3r0r/commit/c8ebd85d9dad17a97218ba6bdff951701869d1df))
* **config:** Refactor configuration management to use CBOR format ([0814d66](https://github.com/jm33-m0/emp3r0r/commit/0814d66e18ee86fef0a8c2b54f265fb6d793bf32))
* enhance JSON config handling with safe extraction methods and add tests ([23a7ee1](https://github.com/jm33-m0/emp3r0r/commit/23a7ee10fefacf1b0438ed565df788f67ef6a5da))
* **ftp:** switch from JSON to CBOR for file stat handling and add corresponding test ([1417c21](https://github.com/jm33-m0/emp3r0r/commit/1417c21f5f44f7754aec562f94fdaa0347cdfeeb))
* **operator:** switch JSON decoder to CBOR in msgTunHandler and add CBOR decoding tests ([8febb75](https://github.com/jm33-m0/emp3r0r/commit/8febb754ae0cf4c118300f3aaeb802f9125d442e))
* switch to CBOR to avoid JSON key strings ([79c6738](https://github.com/jm33-m0/emp3r0r/commit/79c6738fd1f26b408709cc9efe5840a2716ecb82))
* **tls:** TLS configuration for C2 agent server and add tests ([26e1f90](https://github.com/jm33-m0/emp3r0r/commit/26e1f90cd29a9065ec57c0b59de1d5ca7bf2771b))
* update configuration keys in module to use new naming conventions ([a5ef670](https://github.com/jm33-m0/emp3r0r/commit/a5ef670e2458d433ce5845a66bce660f16ba5e26))

## [3.10.1](https://github.com/jm33-m0/emp3r0r/compare/v3.10.0...v3.10.1) (2026-01-04)


### Bug Fixes

* improve agent existence checks and message handling ([2b5ca49](https://github.com/jm33-m0/emp3r0r/commit/2b5ca498659bc6ac3a8883c9ddd39c3288fb8988))
* remove identifiable strings from agent code base ([e63b3de](https://github.com/jm33-m0/emp3r0r/commit/e63b3dec88299c3ad0b434c9f4b526ea90665819))
* sanitise strings ([4dde815](https://github.com/jm33-m0/emp3r0r/commit/4dde8157ad7e7e5308afe0f2ac60e0865a608f90))
* unexport functions for garble ([b311c96](https://github.com/jm33-m0/emp3r0r/commit/b311c96d0a0053407721b5566ca2bdce053ffdaa))

## [3.10.0](https://github.com/jm33-m0/emp3r0r/compare/v3.9.6...v3.10.0) (2026-01-04)


### Features

* update build command to use garble ([ff14c16](https://github.com/jm33-m0/emp3r0r/commit/ff14c16fd69e117aee779a5e7460582d4cf4c486))

## [3.9.6](https://github.com/jm33-m0/emp3r0r/compare/v3.9.5...v3.9.6) (2026-01-04)


### Bug Fixes

* correct RandInt parameter validation and ensure proper range ([7c4c0bf](https://github.com/jm33-m0/emp3r0r/commit/7c4c0bf1cda295171058d86d785a3f7b86c24547))

## [3.9.5](https://github.com/jm33-m0/emp3r0r/compare/v3.9.4...v3.9.5) (2026-01-04)


### Bug Fixes

* improve last handshake management in handleMessageTunnel ([a7bcb42](https://github.com/jm33-m0/emp3r0r/commit/a7bcb429693ca3222311a99d8c0b792b6c989555))

## [3.9.4](https://github.com/jm33-m0/emp3r0r/compare/v3.9.3...v3.9.4) (2026-01-03)


### Bug Fixes

* enhance Socks5Proxy implementation with listener management and synchronization ([cb2047b](https://github.com/jm33-m0/emp3r0r/commit/cb2047bbc4d8b74530f5a91ad6a01b81be2e13cd))

## [3.9.3](https://github.com/jm33-m0/emp3r0r/compare/v3.9.2...v3.9.3) (2026-01-03)


### Bug Fixes

* replace standard log package with custom logging package to eliminate logging strings in agent ([cae377b](https://github.com/jm33-m0/emp3r0r/commit/cae377b97c7d3d49f4b28381f4d48ee75f0f153c))

## [3.9.2](https://github.com/jm33-m0/emp3r0r/compare/v3.9.1...v3.9.2) (2026-01-03)


### Bug Fixes

* data race found in tests ([9db1f78](https://github.com/jm33-m0/emp3r0r/commit/9db1f78ef4fa5da8793b954a6beff6599a0176b1))

## [3.9.1](https://github.com/jm33-m0/emp3r0r/compare/v3.9.0...v3.9.1) (2026-01-01)


### Bug Fixes

* enhance ELF loading security by implementing header stomping and W^X enforcement ([7eeb293](https://github.com/jm33-m0/emp3r0r/commit/7eeb293b640f7a5afbc269ed7132cdbcfdcbd10a))
* implement sleep mask in shellcode stager and enhance process management in payload execution ([5fa1a83](https://github.com/jm33-m0/emp3r0r/commit/5fa1a8381660b2df9890326d5074ed498de18472))
* improve ELF loading security by refining header stomping to target magic bytes ([af33292](https://github.com/jm33-m0/emp3r0r/commit/af33292947e888035a024237f6d34dd4870f6cb5))
* optimise shellcode size ([048ec00](https://github.com/jm33-m0/emp3r0r/commit/048ec0077b8c8905a7696593150419ffdc3d699a))

## [3.9.0](https://github.com/jm33-m0/emp3r0r/compare/v3.8.1...v3.9.0) (2025-12-31)


### Features

* enhance proxy broadcasting with time-based validation and dynamic payloads ([4e97253](https://github.com/jm33-m0/emp3r0r/commit/4e97253d15237a6ea8e7c911a58de1d1a294af77))
* implement mutex for managing reverse connections in SSH proxy ([43bb247](https://github.com/jm33-m0/emp3r0r/commit/43bb247c58a7f9287451e46b1380915128804019))


### Bug Fixes

* always start proxychain when C2 is accessible ([799ec89](https://github.com/jm33-m0/emp3r0r/commit/799ec89907b68e8cf0ec04aebdfde3d639e481af))
* enhance README with new features for APT-grade connectivity and automatic P2P mesh networking ([8817614](https://github.com/jm33-m0/emp3r0r/commit/8817614f0b1df787223070daae7b03156b0ed3ef))
* enhance tag validation in BroadcastServer to include future time slot ([1176e51](https://github.com/jm33-m0/emp3r0r/commit/1176e51f82a315038c865eb7a5f7c3e7599a5380))
* improve proxy handling in BroadcastServer to ensure Shadowsocks is restarted if not working ([d69ec1f](https://github.com/jm33-m0/emp3r0r/commit/d69ec1fdbeacb1d6f59ec070086b6c71cdfa1866))
* make sure shadowsocks is started before validating the broadcasted proxy ([49ba075](https://github.com/jm33-m0/emp3r0r/commit/49ba0752b0b5e153497502bbb4724617c7b1ee15))
* optimize connectivity check in BroadcastServer to reduce log spam when no reverse proxy is connected ([59446ee](https://github.com/jm33-m0/emp3r0r/commit/59446ee788ff88a6a04bd34c29aa6d71398db6b8))
* proxychain is disabled even when `--proxychain` is specified ([f46ce3c](https://github.com/jm33-m0/emp3r0r/commit/f46ce3c5d8d4cca4d8776a5c34a7017caa2dba77))
* update subproject commit reference in emp3r0r.wiki ([329de86](https://github.com/jm33-m0/emp3r0r/commit/329de86fb91da519fb6b97e666a15bb363a30913))

## [3.8.1](https://github.com/jm33-m0/emp3r0r/compare/v3.8.0...v3.8.1) (2025-12-14)


### Bug Fixes

* replace memset with _get_rand for secure memory wiping in elf_load ([e8d1064](https://github.com/jm33-m0/emp3r0r/commit/e8d1064bcbfa5da2aaeacbc9f3c22472bb7561dc))

## [3.8.0](https://github.com/jm33-m0/emp3r0r/compare/v3.7.4...v3.8.0) (2025-12-14)


### Features

* sRDI-like stager ([ff8fcd6](https://github.com/jm33-m0/emp3r0r/commit/ff8fcd6f7563af1ed322394414d17df7e91f0f96))


### Bug Fixes

* disable damonisation to accomodate shellcode and libc stagers ([21de9b3](https://github.com/jm33-m0/emp3r0r/commit/21de9b3ba15af95e975b0153f957dfd610ab0eba))
* ensure build flags can be passed on to `make` ([3de8a46](https://github.com/jm33-m0/emp3r0r/commit/3de8a467003d03a6ddaa68e2dcb563c14bb5af0b))
* update jump_start function to use correct register and improve memory management in malloc and free ([2045f66](https://github.com/jm33-m0/emp3r0r/commit/2045f6689b30601be758331ed8a839cf4bd8d564))

## [3.7.4](https://github.com/jm33-m0/emp3r0r/compare/v3.7.3...v3.7.4) (2025-12-14)


### Bug Fixes

* add ReadIdleTimeout and PingTimeout to HTTP/2 transport for improved connection handling ([e5efd88](https://github.com/jm33-m0/emp3r0r/commit/e5efd8885a82aa0ef2ce0769492ba42ffeb94d24))
* remove read timeout from message tunnel handler, it shouldn't disconnect just because of inactivity ([e39b35f](https://github.com/jm33-m0/emp3r0r/commit/e39b35fb393dafd6346ee0356e5011ea0f35dca7))

## [3.7.3](https://github.com/jm33-m0/emp3r0r/compare/v3.7.2...v3.7.3) (2025-12-13)


### Bug Fixes

* data loss during transmission in UDP stager ([540a477](https://github.com/jm33-m0/emp3r0r/commit/540a4771950cff9d572273f78bbb9fcdd054afd0))
* wipe ELF header in memory if it's in the segment ([b200021](https://github.com/jm33-m0/emp3r0r/commit/b200021178f06360c0143e2d888efa1ef4c16aff))

## [3.7.2](https://github.com/jm33-m0/emp3r0r/compare/v3.7.1...v3.7.2) (2025-12-12)


### Bug Fixes

* add timeout to HTTP client and requests for improved reliability ([dcfc8b7](https://github.com/jm33-m0/emp3r0r/commit/dcfc8b736268bba2b3a20a78010f2762eaebe033))
* implement exponential backoff for agent list refresh and message tunnel connection ([3de26b6](https://github.com/jm33-m0/emp3r0r/commit/3de26b671545ee2fc9733ec08f523c03579adc22))
* increase message channel buffer and implement read timeout for message tunnel ([bda78e5](https://github.com/jm33-m0/emp3r0r/commit/bda78e5b7408a4a0997e0d00cab3f01b55f261ec))

## [3.7.1](https://github.com/jm33-m0/emp3r0r/compare/v3.7.0...v3.7.1) (2025-12-12)


### Bug Fixes

* remove unnecessary rwx when mapping stack ([77126cb](https://github.com/jm33-m0/emp3r0r/commit/77126cbc84634f35d825dd13fc8e4ed3aba1ad68))

## [3.7.0](https://github.com/jm33-m0/emp3r0r/compare/v3.6.0...v3.7.0) (2025-12-12)


### Features

* implement TCP and UDP listener support and enhance download functionality ([c6ff3cc](https://github.com/jm33-m0/emp3r0r/commit/c6ff3ccc42375304660990819522fa5b977aa45e))
* implement XOR encoding for configuration strings and enhance security ([e78c2c6](https://github.com/jm33-m0/emp3r0r/commit/e78c2c67f926d150ad8586bb9faa0508d51690ef))


### Bug Fixes

* enhance stager configuration to support multiple listener types and update documentation ([7ec4fe0](https://github.com/jm33-m0/emp3r0r/commit/7ec4fe0494275719ccd4315776ba89a9148ce0e0))
* replace /dev/urandom with getrandom() syscall for improved randomness retrieval ([e2c9fa9](https://github.com/jm33-m0/emp3r0r/commit/e2c9fa9d7e6dcac4e1a2edf99e895405c6caae16))
* streamline agent and stager code by removing unused persistence logic and enhancing debug error handling ([ada195a](https://github.com/jm33-m0/emp3r0r/commit/ada195a9b79ab2f81da5a00bfbdc3bebdf5878a1))

## [3.6.0](https://github.com/jm33-m0/emp3r0r/compare/v3.5.1...v3.6.0) (2025-12-12)


### Features

* build Linux stager as executable ([2b8c404](https://github.com/jm33-m0/emp3r0r/commit/2b8c40450f6af41f26cf9b47d79efa91442dc690))
* use linux stager as orchestrator and ensure emp3r0r agent payload stay encrypted in memory when idle ([013d95c](https://github.com/jm33-m0/emp3r0r/commit/013d95cfc7f558c5a56d8bd7eb84a0cc11df0b48))


### Bug Fixes

* ensure conditional c2 check happens before anything else ([347818e](https://github.com/jm33-m0/emp3r0r/commit/347818e20e8da03d6cf4f664cf08c0e532ba420a))
* garbage charaters being printed in tmux ([3ebdbb7](https://github.com/jm33-m0/emp3r0r/commit/3ebdbb76bac0644ffa5129f3db73ddbb74a7b4a6))
* improve conditionalC2FailNotify to ensure it only acts when started by a stager ([7d43afc](https://github.com/jm33-m0/emp3r0r/commit/7d43afc64b642b72007a5610b0b296c1eb9a48dd))
* inconsistency in wg/mtls operator connections ([dda9332](https://github.com/jm33-m0/emp3r0r/commit/dda9332a5ccf13c2c854693ff61b2aa8c4410149))
* update connection error handling to signal parent and exit instead of retrying ([c812887](https://github.com/jm33-m0/emp3r0r/commit/c8128879bedb9da15898c9a4d9347c8ef953543a))
* update DownloadExtractConfig to use client-specific config path when not running as server ([e2a9fc3](https://github.com/jm33-m0/emp3r0r/commit/e2a9fc3f1deafe351020999e337167019a599d25))
* update stager executable build to use musl-gcc with static linking ([1a2cec6](https://github.com/jm33-m0/emp3r0r/commit/1a2cec6f11e696ecd2a7505e3650f09ebb45c9bf))

## [3.5.1](https://github.com/jm33-m0/emp3r0r/compare/v3.5.0...v3.5.1) (2025-12-11)


### Bug Fixes

* downloader file name messed up ([8ba18d6](https://github.com/jm33-m0/emp3r0r/commit/8ba18d65990306e2a399f2619f8d4f6ae2215e12))
* prompt doesn't work, and local modules don't need prompts ([0406a3a](https://github.com/jm33-m0/emp3r0r/commit/0406a3a7c305bde46814a749a58b9ae03b5cb547))

## [3.5.0](https://github.com/jm33-m0/emp3r0r/compare/v3.4.2...v3.5.0) (2025-12-11)


### Features

* add `Fileless` property to modules, warn users if there will be file dropping on the target ([c552e4a](https://github.com/jm33-m0/emp3r0r/commit/c552e4ad98399f01e4d5271e5a2418331f0afe67))
* remove `AgentRoot` auto-creation ([eeddd07](https://github.com/jm33-m0/emp3r0r/commit/eeddd0726e643e9d6bce74d18d403d4f5027e7d6))
* unify file operations in agent for future anti-detection features ([ebdf490](https://github.com/jm33-m0/emp3r0r/commit/ebdf490a078854c798803fa90e96add1a7378c7f))


### Bug Fixes

* change file name suffix for better stealth ([3231f3d](https://github.com/jm33-m0/emp3r0r/commit/3231f3deef7dde081eb9be28f1e97b842686ea6c))
* copy new builder script when packaging ([7df846b](https://github.com/jm33-m0/emp3r0r/commit/7df846b95bdee2cfea4fbf1584c7f316333a32f6))
* improve launcher UX ([7dc08c4](https://github.com/jm33-m0/emp3r0r/commit/7dc08c485131f1060fe768b901d6f583d76d0c2a))
* refactor `emp3r0r` script to separate builder and launcher ([e681e0d](https://github.com/jm33-m0/emp3r0r/commit/e681e0d088c367e848acc9a6359928a4341f5224))
* refactor `screenshot` to make it a module ([05c4bde](https://github.com/jm33-m0/emp3r0r/commit/05c4bde3e9d5badff10906a46457b93cc163352b))
* some OPSEC improvements for the Linux stager ([df5ef29](https://github.com/jm33-m0/emp3r0r/commit/df5ef29aabaf00dcb517bba7e0c81665b7041f18))
* update deps ([0d6c93c](https://github.com/jm33-m0/emp3r0r/commit/0d6c93ceec5190b1ceb99df41d5a90151946cd3d))

## [3.4.2](https://github.com/jm33-m0/emp3r0r/compare/v3.4.1...v3.4.2) (2025-06-19)


### Bug Fixes

* enhance logging messages for server startup with success indicators ([f26796d](https://github.com/jm33-m0/emp3r0r/commit/f26796d232862ac333d426687e9d9f7347eeae45))
* ensure tmux title truncation to 10 characters ([d5e819b](https://github.com/jm33-m0/emp3r0r/commit/d5e819bf708cd59771ae4456a2a863e11357397e))

## [3.4.1](https://github.com/jm33-m0/emp3r0r/compare/v3.4.0...v3.4.1) (2025-06-18)


### Bug Fixes

* add target_path option to elf_patch command for custom library loading location ([dc2b009](https://github.com/jm33-m0/emp3r0r/commit/dc2b009ecd4c1b807d7f575ddba286479e663fdd))
* copy timestamps from ELF file to SO file in ElfPatcher function ([4b6fdb8](https://github.com/jm33-m0/emp3r0r/commit/4b6fdb8eddea662aaf7a1a6c62214089036c7c51))

## [3.4.0](https://github.com/jm33-m0/emp3r0r/compare/v3.3.2...v3.4.0) (2025-06-17)


### Features

* add bind address option for port forwarding sessions, closes [#476](https://github.com/jm33-m0/emp3r0r/issues/476) ([c4374aa](https://github.com/jm33-m0/emp3r0r/commit/c4374aaf170faa1988dcd3bd9583c118349d485a))

## [3.3.2](https://github.com/jm33-m0/emp3r0r/compare/v3.3.1...v3.3.2) (2025-06-16)


### Bug Fixes

* add `!elf_patch` command to patch ELF files and load shared libraries, replacing `get_persistence` ([bf113f3](https://github.com/jm33-m0/emp3r0r/commit/bf113f38188a5b944b401ac062b432da3be48803))

## [3.3.1](https://github.com/jm33-m0/emp3r0r/compare/v3.3.0...v3.3.1) (2025-06-14)


### Bug Fixes

* clarify error message for missing C2 server IP in WireGuard connection ([0dcf091](https://github.com/jm33-m0/emp3r0r/commit/0dcf091a5704547f3eee86a25f489520b380b2a9))
* do not validate upload response ([d06922a](https://github.com/jm33-m0/emp3r0r/commit/d06922ab29aecd453b29ab1b4a201ab1d9545dde))
* remove unused dependencies and simplify line wrapping functionality ([71db5e3](https://github.com/jm33-m0/emp3r0r/commit/71db5e346b8040001b2c12144248015aaa856262))
* **server:** add command generation for client connections and improve usage instructions ([c5437c2](https://github.com/jm33-m0/emp3r0r/commit/c5437c2bfb53e1ca6de31c90a90e424cab336f02))
* simplify table rendering and add reset layout command ([ca5c066](https://github.com/jm33-m0/emp3r0r/commit/ca5c0669a6e469cbcd2d669e2af050379c5c16d8))
* **tmux:** add pane layout reset functionality and improve pane size constraints ([a9b8c23](https://github.com/jm33-m0/emp3r0r/commit/a9b8c23b8e1bcda367d2a8f7a31b1c30894bdc09))
* update carapace dependency and remove obsolete references ([bfcf031](https://github.com/jm33-m0/emp3r0r/commit/bfcf0319ebb7205e7c0b4ab8a9f9eada9aa5c43e))
* update command formatting for client connection commands and improve readability ([679b312](https://github.com/jm33-m0/emp3r0r/commit/679b312b7cd57e36122d6e8f31bfd9a4651f4b73))

## [3.3.0](https://github.com/jm33-m0/emp3r0r/compare/v3.2.2...v3.3.0) (2025-06-13)


### Features

* **generate:** enhance payload type descriptions for CGO support [#473](https://github.com/jm33-m0/emp3r0r/issues/473) ([fdb6d33](https://github.com/jm33-m0/emp3r0r/commit/fdb6d33f692370c47f53660da941db2304c2b4be))
* **kill:** enhance process killing functionality with improved error handling and support for multiple PIDs [#468](https://github.com/jm33-m0/emp3r0r/issues/468) ([ddf0560](https://github.com/jm33-m0/emp3r0r/commit/ddf05607bc250ff5e3a1be4da0a3d055cbdeb9b7))
* **release:** update permissions and enhance upload script with response handling ([6feaaff](https://github.com/jm33-m0/emp3r0r/commit/6feaaff18d5800f7641243418c8e28289697f32c))


### Bug Fixes

* 468 ([36d0457](https://github.com/jm33-m0/emp3r0r/commit/36d045786c1f11feea9d3e91300062f613676847))
* **moduleCmd:** improve error handling for ActiveModule and command execution [#474](https://github.com/jm33-m0/emp3r0r/issues/474) ([06c0c5e](https://github.com/jm33-m0/emp3r0r/commit/06c0c5e65a2e4a2f4b9b02edc7a42c708252f27f))

## [3.2.2](https://github.com/jm33-m0/emp3r0r/compare/v3.2.1...v3.2.2) (2025-03-12)


### Bug Fixes

* update deps ([cfaac67](https://github.com/jm33-m0/emp3r0r/commit/cfaac675bde3aca7e46b4c113d0d3e64b3eedbe0))

## [3.2.1](https://github.com/jm33-m0/emp3r0r/compare/v3.2.0...v3.2.1) (2025-03-06)


### Bug Fixes

* upgrade `github.com/jm33-m0/arc` to `v2` ([3a12a5d](https://github.com/jm33-m0/emp3r0r/commit/3a12a5d376fc470daf6220669a097aa4d2093e0b))

## [3.2.0](https://github.com/jm33-m0/emp3r0r/compare/v3.1.4...v3.2.0) (2025-03-06)


### Features

* set up auto-completion during installation ([8d3553a](https://github.com/jm33-m0/emp3r0r/commit/8d3553a521f4773485d42f57dc035654966eb137))
* support multiple operators ([99123f1](https://github.com/jm33-m0/emp3r0r/commit/99123f137c41bb6731790139bbb9fed0d395b7a7))


### Bug Fixes

* `copy_stub` is slow, move it out of `init` ([dc9bc84](https://github.com/jm33-m0/emp3r0r/commit/dc9bc84d5f410d082b0424143e1ad0c9caa3808b))
* unable to get `SUDO_USER` when installing ([743fffe](https://github.com/jm33-m0/emp3r0r/commit/743fffe8fde7b86e7a43339cf20a706cb8a41d30))
* uninstall shell completion files as well ([2e1a7c1](https://github.com/jm33-m0/emp3r0r/commit/2e1a7c12cfdaea180f4ab6b7a7e60c255d75e788))
* UX in starting server ([3408aa7](https://github.com/jm33-m0/emp3r0r/commit/3408aa7001f46eac7e90e0d2055c9d6e271aee3a))
* wg IPs not random ([19684f7](https://github.com/jm33-m0/emp3r0r/commit/19684f7b6e4df8a91143b1784382e6567ecbcdca))

## [3.1.4](https://github.com/jm33-m0/emp3r0r/compare/v3.1.3...v3.1.4) (2025-03-05)


### Bug Fixes

* optimize HTTP2 connections ([91fcd5a](https://github.com/jm33-m0/emp3r0r/commit/91fcd5ac584c4761fb71f650083de8179a7f9fb9))
* simplify agent binary patching ([8f3e9a1](https://github.com/jm33-m0/emp3r0r/commit/8f3e9a1d1438d2fc56403862816cc64a563fe068))

## [3.1.3](https://github.com/jm33-m0/emp3r0r/compare/v3.1.2...v3.1.3) (2025-03-04)


### Bug Fixes

* existing config file causes operator to fail ([4bea0ef](https://github.com/jm33-m0/emp3r0r/commit/4bea0efe074355b3fd5f813625292bf37eb48cbd))
* run jobs in the background to prevent blocking ([317be9c](https://github.com/jm33-m0/emp3r0r/commit/317be9cf63c7c2f4f64369e390204500d6b8182a))
* screenshot ([45d7eaf](https://github.com/jm33-m0/emp3r0r/commit/45d7eafd8375664a3c860ec56dc6163746cfce0e))

## [3.1.2](https://github.com/jm33-m0/emp3r0r/compare/v3.1.1...v3.1.2) (2025-03-04)


### Bug Fixes

* `run_proxy` cmd sender ([1e854c0](https://github.com/jm33-m0/emp3r0r/commit/1e854c088d54705400acd95d7980941965b071db))
* `ssh` shells and port mapping ([4bcd79f](https://github.com/jm33-m0/emp3r0r/commit/4bcd79fb79bb463870b9f076c844524d534d7e40))
* modules should be able to run from operator ([a837e4f](https://github.com/jm33-m0/emp3r0r/commit/a837e4fb7351a3c4d812c74209783ef683b878f2))
* operator needs to pull the latest certs from server every time it runs ([b330ee6](https://github.com/jm33-m0/emp3r0r/commit/b330ee6a9e67f4ebe4b5e306c4f34df91989671e))
* refactor cmd line usage ([84ec8c3](https://github.com/jm33-m0/emp3r0r/commit/84ec8c3314baa5e06b62cf28922d05aac4e32cc0))
* some noticeable latency in agent list refreshing ([c5b4d71](https://github.com/jm33-m0/emp3r0r/commit/c5b4d71ac5b62cee471cd3a2c5c140c31d47e0db))

## [3.1.1](https://github.com/jm33-m0/emp3r0r/compare/v3.1.0...v3.1.1) (2025-03-02)


### Bug Fixes

* `cd` ([1a674e4](https://github.com/jm33-m0/emp3r0r/commit/1a674e40c2a295ca16ff7b4bf308eabec0be6e1f))
* auto-complete agent names ([4280495](https://github.com/jm33-m0/emp3r0r/commit/4280495db6e97c971f3a9be93e4432dbcf1f0e95))
* auto-complete remote dir ([23f3774](https://github.com/jm33-m0/emp3r0r/commit/23f3774a8b852df3cd4a7a32e95382c3cba062d4))
* command sender in `ftp` package ([6d3a96f](https://github.com/jm33-m0/emp3r0r/commit/6d3a96f2ace89e4a995cb8d4adbc164e68802940))
* command time tracking ([030639d](https://github.com/jm33-m0/emp3r0r/commit/030639d45a6ee439a5cad67ec7178d4f78f8c466))
* crash ([4d3df48](https://github.com/jm33-m0/emp3r0r/commit/4d3df48c757415eddf4ae9102340559c3cbfb5ec))
* make sure commands have UUID for tracking ([08b89b0](https://github.com/jm33-m0/emp3r0r/commit/08b89b0b319d079854b05e64ab9231feceec940c))

## [3.1.0](https://github.com/jm33-m0/emp3r0r/compare/v3.0.0...v3.1.0) (2025-03-02)


### Features

* operator can pull config tarball from server via wireguard ([d872e59](https://github.com/jm33-m0/emp3r0r/commit/d872e59a96b24df97d96abf883163672f07ac316))
* wireguard auto-config as operator transport ([27c93ab](https://github.com/jm33-m0/emp3r0r/commit/27c93ab7475a9c302999ae7c48af90b086b28ca0))


### Bug Fixes

* `get` and `put` file transfer features ([5bcb259](https://github.com/jm33-m0/emp3r0r/commit/5bcb259643b7958e0c629c6b886d0bbb0b444480))
* set active agent (WIP) ([01b9840](https://github.com/jm33-m0/emp3r0r/commit/01b98408caae14f9ffb6a527a75ede7f7ca5e227))

## [3.0.0](https://github.com/jm33-m0/emp3r0r/compare/v2.4.3...v3.0.0) (2025-02-28)


### ⚠ BREAKING CHANGES

* separate `core` and `server`, adopting operator-server mode (WIP)

### Features

* assign `cap_net_admin` to `emp3r0r-cc` when installing ([18db26c](https://github.com/jm33-m0/emp3r0r/commit/18db26c4ebb716988fd019d494a31cd81d4404a8))
* relay file transfer requests to operator ([012884e](https://github.com/jm33-m0/emp3r0r/commit/012884e63f23b3d33b6b8f7df2aa6e7a59fa573e))
* relay message tunnel to operator ([eb3ac70](https://github.com/jm33-m0/emp3r0r/commit/eb3ac702b7758175ff26acb33505098c1b2a18df))
* tar config dir for operator to use when server starts ([4c38418](https://github.com/jm33-m0/emp3r0r/commit/4c3841844070ab825dd5ace3f6f6113ca7d60866))
* wireguard operator ([a2016cf](https://github.com/jm33-m0/emp3r0r/commit/a2016cf24f3c00c45704b5a35b886c89e81cde4c))
* wireguard operator management ([8d09db0](https://github.com/jm33-m0/emp3r0r/commit/8d09db09cd6f17ef2fed0051dde9f14bfdcaca5b))
* wireguard-go ([ea73568](https://github.com/jm33-m0/emp3r0r/commit/ea73568e54fc388c4e6fd1954a90e40032cff425))


### Bug Fixes

* `put --dst` auto-complete ([f6e9f5a](https://github.com/jm33-m0/emp3r0r/commit/f6e9f5a0bf0e59741b5f5cda7fbcd77046bcddbd))
* critical bug: `emp3r0r.json` gets overwritten every time `cc` starts ([8259507](https://github.com/jm33-m0/emp3r0r/commit/825950737b5a90a029d7ce97cb9a1d4a3e15f701))
* do not log if run as agent ([6325a67](https://github.com/jm33-m0/emp3r0r/commit/6325a67597fec882832350694432beb2cc415c62))
* search `c:\` when run as priviliged user ([4cc1dc0](https://github.com/jm33-m0/emp3r0r/commit/4cc1dc0e8546be469f1eaf21efcc28937a4b3f15))
* simplify ssh c2 relay ([f280459](https://github.com/jm33-m0/emp3r0r/commit/f28045920152b7dab28d2ea2c0dc7eddf7580289))
* unify server response to unauthorized requests ([1146adc](https://github.com/jm33-m0/emp3r0r/commit/1146adcd634946a48e5371dcbb7f4810dc040094))


### Code Refactoring

* separate `core` and `server`, adopting operator-server mode (WIP) ([d4d52b1](https://github.com/jm33-m0/emp3r0r/commit/d4d52b1372122fd6bf9847349f09ddf8c2ef1de5))
