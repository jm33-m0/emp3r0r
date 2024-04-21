# Changelog

## [1.37.1](https://github.com/jm33-m0/emp3r0r/compare/v1.37.0...v1.37.1) (2024-04-21)


### Bug Fixes

* update deps ([f401df2](https://github.com/jm33-m0/emp3r0r/commit/f401df25736889402d66719b2bee6588e8faf168))

## [1.37.0](https://github.com/jm33-m0/emp3r0r/compare/v1.36.0...v1.37.0) (2024-04-03)


### Features

* deprecate `gen_agent` cmd in favor of `use gen_agent` module ([add0a7e](https://github.com/jm33-m0/emp3r0r/commit/add0a7eb1b0a0ed916a4b298c4712661421783e9))


### Bug Fixes

* `__libc_dlopen_mode` not found ([322d071](https://github.com/jm33-m0/emp3r0r/commit/322d0719fcb9182b5f5a94e071ad367e9d585eec))
* throw error if shellcode is empty ([06b6549](https://github.com/jm33-m0/emp3r0r/commit/06b654961829f8cd4924848ca8448e7129201000))
* update deps ([298f87c](https://github.com/jm33-m0/emp3r0r/commit/298f87c380adfa13c90c656bec5cf3e5c3517e63))

## [1.36.0](https://github.com/jm33-m0/emp3r0r/compare/v1.35.3...v1.36.0) (2024-01-31)


### Features

* module help for `gen_agent` ([ea3cfe7](https://github.com/jm33-m0/emp3r0r/commit/ea3cfe7c7c8eac444d63662f894b9ef9c016f05b))


### Bug Fixes

* `gen_agent` should abort when OS choice is invalid ([a8c2142](https://github.com/jm33-m0/emp3r0r/commit/a8c21423e9d4ef672ac163575f17b2d54fde550b))
* auto-complete `gen_agent` module options ([71e7d79](https://github.com/jm33-m0/emp3r0r/commit/71e7d79fc5621db731d53a6f205143d0ea889792))
* do not prompt for indicator text when it's disabled ([f6e8c62](https://github.com/jm33-m0/emp3r0r/commit/f6e8c62b7f35e9cb90906be9c53b70cdb6be7186))
* reduce CPU load ([2f5ed34](https://github.com/jm33-m0/emp3r0r/commit/2f5ed34f72ca41d44d2e08a8747307a9ba631fa3))

## [1.35.3](https://github.com/jm33-m0/emp3r0r/compare/v1.35.2...v1.35.3) (2024-01-30)


### Bug Fixes

* long lines in `System Info` pane ([ef6f1d9](https://github.com/jm33-m0/emp3r0r/commit/ef6f1d925abc8f2127c32f17b2d1ad3f68f6b32a))
* panic on HTTP2 server ([45d0ff7](https://github.com/jm33-m0/emp3r0r/commit/45d0ff786581c8078db789c0b8493620131878ee))

## [1.35.2](https://github.com/jm33-m0/emp3r0r/compare/v1.35.1...v1.35.2) (2024-01-30)


### Bug Fixes

* [#292](https://github.com/jm33-m0/emp3r0r/issues/292) DLL agent ([dddd442](https://github.com/jm33-m0/emp3r0r/commit/dddd4421f9f103d31b2f80acb7ff4faf1fe76014))

## [1.35.1](https://github.com/jm33-m0/emp3r0r/compare/v1.35.0...v1.35.1) (2024-01-29)


### Bug Fixes

* igonore cmdline args when run as DLL ([4dd830e](https://github.com/jm33-m0/emp3r0r/commit/4dd830e64920c9de9e35bff3e93e34cacd9b12f3))

## [1.35.0](https://github.com/jm33-m0/emp3r0r/compare/v1.34.10...v1.35.0) (2024-01-24)


### Features

* support DLL agent stub (`amd64` only) ([eda0e94](https://github.com/jm33-m0/emp3r0r/commit/eda0e94cc30f82bc80b6e4dbbcddffded8da4265))


### Bug Fixes

* `-gencert` refuses to work when `emp3r0r.json` not found ([f100936](https://github.com/jm33-m0/emp3r0r/commit/f100936ef288eadb6045c67bc5d1c165fa0f9c5b))
* refactor: merge Linux/Windows agent code ([db70d70](https://github.com/jm33-m0/emp3r0r/commit/db70d702dad6e7033310b9c7cbecd57a5bc2aed7))

## [1.34.10](https://github.com/jm33-m0/emp3r0r/compare/v1.34.9...v1.34.10) (2024-01-22)


### Bug Fixes

* tmux keeps switching back to home window ([ad9d887](https://github.com/jm33-m0/emp3r0r/commit/ad9d887989890037f0b818d2c1a03b40af376c92))

## [1.34.9](https://github.com/jm33-m0/emp3r0r/compare/v1.34.8...v1.34.9) (2024-01-22)


### Bug Fixes

* [#244](https://github.com/jm33-m0/emp3r0r/issues/244) ([50a0221](https://github.com/jm33-m0/emp3r0r/commit/50a0221c614c831f426086a5a15f914fcb70cee6))
* agent system info pane not being updated ([5e9a8ab](https://github.com/jm33-m0/emp3r0r/commit/5e9a8abb2755076e2fdf80a62517ad2d933ab91a))
* remove unnecessary colors in "system info" ([ca14ba1](https://github.com/jm33-m0/emp3r0r/commit/ca14ba1c11a572de354ca1a74ea7247a6e0db10f))
* word wrapping issues ([9ab1786](https://github.com/jm33-m0/emp3r0r/commit/9ab178673b50af9595ab897b456d030919ae4726))

## [1.34.8](https://github.com/jm33-m0/emp3r0r/compare/v1.34.7...v1.34.8) (2024-01-19)


### Bug Fixes

* CC unable to detect existing instance ([15e2940](https://github.com/jm33-m0/emp3r0r/commit/15e2940c1fd379eb2666bd82c2b69f44f2d78519))
* incomplete downloads cannot be resumed ([bbd57f9](https://github.com/jm33-m0/emp3r0r/commit/bbd57f98e93fe44d37e339b0708e21742c8fa66d))

## [1.34.7](https://github.com/jm33-m0/emp3r0r/compare/v1.34.6...v1.34.7) (2024-01-18)


### Bug Fixes

* connectivity check should connect to C2 using uTLS ([8b746c5](https://github.com/jm33-m0/emp3r0r/commit/8b746c5bf38e6300362e8b42f750c1f1e83e0fb9))

## [1.34.6](https://github.com/jm33-m0/emp3r0r/compare/v1.34.5...v1.34.6) (2024-01-17)


### Bug Fixes

* `passProxy` proxy URL parsing error ([957395e](https://github.com/jm33-m0/emp3r0r/commit/957395edc369dbf51463af11d061c2421a20343d))

## [1.34.5](https://github.com/jm33-m0/emp3r0r/compare/v1.34.4...v1.34.5) (2024-01-17)


### Bug Fixes

* `bring2cc` fails to connect configure SOCKS5 proxy ([d11c8f0](https://github.com/jm33-m0/emp3r0r/commit/d11c8f08c802d9a9662e603f6a6611e751c0d0a1))
* `bring2cc` should start SOCKS5 server automatically ([48b7311](https://github.com/jm33-m0/emp3r0r/commit/48b7311dc3096e2cd9e3f9047cd64b3a03e1b48b))
* auto proxy broken ([7b04571](https://github.com/jm33-m0/emp3r0r/commit/7b045715213229b2afb10d9ee71416bbefd29b31))

## [1.34.4](https://github.com/jm33-m0/emp3r0r/compare/v1.34.3...v1.34.4) (2024-01-16)


### Bug Fixes

* `-connect_relay` unable to recovery SSH session ([8bde2fb](https://github.com/jm33-m0/emp3r0r/commit/8bde2fbc7aa9b215e8b0cf8f3fc6a85f56b3e964))

## [1.34.3](https://github.com/jm33-m0/emp3r0r/compare/v1.34.2...v1.34.3) (2024-01-16)


### Bug Fixes

* agent aborts connection (Windows) ([8c73193](https://github.com/jm33-m0/emp3r0r/commit/8c731935b440ff4828ed4aa23bc8ee8bd6148f31))
* agent aborts connection when C2 is unreachable ([def1b2a](https://github.com/jm33-m0/emp3r0r/commit/def1b2a453931dc8e2490749b649720b6eedb289))
* show C2 address in agent system info ([7032d34](https://github.com/jm33-m0/emp3r0r/commit/7032d34c0d546264335664048213d0a9767010ec))
* ssh C2 relay client should retry connection until SSH session is established ([966147b](https://github.com/jm33-m0/emp3r0r/commit/966147b4f0199022576141aeef93c99bfff78972))

## [1.34.2](https://github.com/jm33-m0/emp3r0r/compare/v1.34.1...v1.34.2) (2024-01-13)


### Bug Fixes

* add instructions ([c051806](https://github.com/jm33-m0/emp3r0r/commit/c051806a6c042501658623b26ade3d7995b6baf0))
* emp3r0r should exit after executing `-gencert` ([33edc36](https://github.com/jm33-m0/emp3r0r/commit/33edc36d40861324a1dac6d980978d4150ceaca1))

## [1.34.1](https://github.com/jm33-m0/emp3r0r/compare/v1.34.0...v1.34.1) (2024-01-13)


### Bug Fixes

* C2 relay client ([7e121d6](https://github.com/jm33-m0/emp3r0r/commit/7e121d664b2cc9eaaeb2cf4b316f11e7c25d29e1))
* C2 relay: C2 service not running ([4a26931](https://github.com/jm33-m0/emp3r0r/commit/4a2693135df576c5b86f7c6c0197069d0c772d69))

## [1.34.0](https://github.com/jm33-m0/emp3r0r/compare/v1.33.5...v1.34.0) (2024-01-13)


### Features

* C2 relay via SSH ([522b6b3](https://github.com/jm33-m0/emp3r0r/commit/522b6b37779d34d674ed4bc47842692ef944875f))

## [1.33.5](https://github.com/jm33-m0/emp3r0r/compare/v1.33.4...v1.33.5) (2024-01-11)


### Bug Fixes

* bash stager unable to execute agent ([f406100](https://github.com/jm33-m0/emp3r0r/commit/f4061006fe50b79730e186e204cc2a20611416cc))
* help user understand how stager URL works ([71905e5](https://github.com/jm33-m0/emp3r0r/commit/71905e57775d3c969cc6ce010aa9862af8610bc8))
* prefer custom bash binary ([9c13feb](https://github.com/jm33-m0/emp3r0r/commit/9c13febeed5556691ca10b4d7d551110dfa302ad))
* update deps ([2aabc1e](https://github.com/jm33-m0/emp3r0r/commit/2aabc1e3d70b9d5a37b3c80f0c3c452dcc44e947))
* use base64 encoding for bash stager ([4d9657c](https://github.com/jm33-m0/emp3r0r/commit/4d9657c5edb22c6c5474d55d38ec365601396201))

## [1.33.4](https://github.com/jm33-m0/emp3r0r/compare/v1.33.3...v1.33.4) (2023-12-25)


### Bug Fixes

* no error reported when `lpe_helper` fails ([39284ab](https://github.com/jm33-m0/emp3r0r/commit/39284ab9645f8597d5962055d8a45e6ea198f751))
* scripts unable to run ([32a808a](https://github.com/jm33-m0/emp3r0r/commit/32a808aa37a646b1a64e60fcfb347f892ccbd4fe))
* tmux history length too small ([c15fe26](https://github.com/jm33-m0/emp3r0r/commit/c15fe26a0151adabb113ec73df05abd41b993302))
* winpeas: support both ps1 and batch format ([0ebd71c](https://github.com/jm33-m0/emp3r0r/commit/0ebd71c0b5d89c01b1b7a3b86d36c0f28704063d))

## [1.33.3](https://github.com/jm33-m0/emp3r0r/compare/v1.33.2...v1.33.3) (2023-12-25)


### Bug Fixes

* `go-console` fails to start winpty ([e7e2939](https://github.com/jm33-m0/emp3r0r/commit/e7e2939b572053e44d3b41c5cc6bd8635b7958f1))

## [1.33.2](https://github.com/jm33-m0/emp3r0r/compare/v1.33.1...v1.33.2) (2023-12-25)


### Bug Fixes

* `lpe_winpeas` for Windows LPE ([a79f8a2](https://github.com/jm33-m0/emp3r0r/commit/a79f8a2b4e260dcbaa71465214acd5cd90c217af))
* `split-window -l` needs `%` to specify percentage ([266f195](https://github.com/jm33-m0/emp3r0r/commit/266f195a6ac932ea9b3000b027dc668c3008160f))
* `split-window -p &lt;size&gt;` has been deprecated in tmux newer versions ([d625d87](https://github.com/jm33-m0/emp3r0r/commit/d625d87d0ca2d2f7b4e0bf69e4decae06da037ec))
* trying to obtain output ([b90975f](https://github.com/jm33-m0/emp3r0r/commit/b90975f3ef7ec71963b1e47134bc11b13710511b))

## [1.33.1](https://github.com/jm33-m0/emp3r0r/compare/v1.33.0...v1.33.1) (2023-12-22)


### Bug Fixes

* `lpe_linpeas` unable to run ([a32187f](https://github.com/jm33-m0/emp3r0r/commit/a32187f7bd776a7e364405330bfd304964cf1855))

## [1.33.0](https://github.com/jm33-m0/emp3r0r/compare/v1.32.5...v1.33.0) (2023-12-22)


### Features

* remove shell pane ([86851d2](https://github.com/jm33-m0/emp3r0r/commit/86851d2a55000f50a3c149b349032f0dc199a577))
* revamp `lpe_helper` ([94d3601](https://github.com/jm33-m0/emp3r0r/commit/94d3601ce45baa4df8af019a03e5f2d46ab056d1))


### Bug Fixes

* `grab` creates on-disk file even if no path is specified ([dfbf640](https://github.com/jm33-m0/emp3r0r/commit/dfbf640276bc46819df6b526421ae1ea34ba2ec5))
* tmux config: status bar scripts not working ([db9ba69](https://github.com/jm33-m0/emp3r0r/commit/db9ba6990a62de520557db29ee2c64e5aa7b7441))

## [1.32.5](https://github.com/jm33-m0/emp3r0r/compare/v1.32.4...v1.32.5) (2023-12-22)


### Bug Fixes

* 1. option to disable NCSI check 2. upgrade deps ([5a14b7a](https://github.com/jm33-m0/emp3r0r/commit/5a14b7a741e905a64c3d3b05db0643bd2ce0b840))

## [1.32.4](https://github.com/jm33-m0/emp3r0r/compare/v1.32.3...v1.32.4) (2023-11-23)


### Bug Fixes

* [#250](https://github.com/jm33-m0/emp3r0r/issues/250) ([c01340d](https://github.com/jm33-m0/emp3r0r/commit/c01340d2651ce5ab4260b1955b23fac6fbf1c57f))

## [1.32.3](https://github.com/jm33-m0/emp3r0r/compare/v1.32.2...v1.32.3) (2023-11-22)


### Bug Fixes

* [#248](https://github.com/jm33-m0/emp3r0r/issues/248) ([e89155d](https://github.com/jm33-m0/emp3r0r/commit/e89155d2c14a73ed7d834be214ced9d0ada37227))

## [1.32.2](https://github.com/jm33-m0/emp3r0r/compare/v1.32.1...v1.32.2) (2023-11-02)


### Bug Fixes

* `FileBaseName` needs to strip `/` ([4eca34b](https://github.com/jm33-m0/emp3r0r/commit/4eca34b651c01abf61c1b5a64221a78146516136))

## [1.32.1](https://github.com/jm33-m0/emp3r0r/compare/v1.32.0...v1.32.1) (2023-10-11)


### Bug Fixes

* [#264](https://github.com/jm33-m0/emp3r0r/issues/264) add option to disable timeout in proxy altogether ([e8b31e5](https://github.com/jm33-m0/emp3r0r/commit/e8b31e59d5d439e1dff143a541e8c0a67d0141ec))
* [#264](https://github.com/jm33-m0/emp3r0r/issues/264) disable timeout and leave cleanup job to the OS ([d3cea97](https://github.com/jm33-m0/emp3r0r/commit/d3cea97539474e779d1a03c1f7cd805c8e84893c))

## [1.32.0](https://github.com/jm33-m0/emp3r0r/compare/v1.31.12...v1.32.0) (2023-10-10)


### Features

* upgrade tmux config ([d5fc0d0](https://github.com/jm33-m0/emp3r0r/commit/d5fc0d0edcf944c2089071b855f12d56b62edbe3))


### Bug Fixes

* [#264](https://github.com/jm33-m0/emp3r0r/issues/264) increase timeout to 2 minutes ([cc7034d](https://github.com/jm33-m0/emp3r0r/commit/cc7034d3914295ccf55fffa87e9269b7126b6d3d))

## [1.31.12](https://github.com/jm33-m0/emp3r0r/compare/v1.31.11...v1.31.12) (2023-10-08)


### Bug Fixes

* upgrade `mholt/archiver` ([898e4a4](https://github.com/jm33-m0/emp3r0r/commit/898e4a499d8558b4e016713fbdb926d4a849e11b))

## [1.31.11](https://github.com/jm33-m0/emp3r0r/compare/v1.31.10...v1.31.11) (2023-10-08)


### Bug Fixes

* security issue in `archiver` ([ffd261e](https://github.com/jm33-m0/emp3r0r/commit/ffd261e610ddbc77fcaf9c197b5c5d8fc7d1f22f))

## [1.31.10](https://github.com/jm33-m0/emp3r0r/compare/v1.31.9...v1.31.10) (2023-09-21)


### Bug Fixes

* inaccurate waitqueue count ([4eeacf6](https://github.com/jm33-m0/emp3r0r/commit/4eeacf6af9dd5881fdf3311b59f67061bad9cac3))
* persistence using profiles ([#260](https://github.com/jm33-m0/emp3r0r/issues/260)) ([409f51c](https://github.com/jm33-m0/emp3r0r/commit/409f51cbf16ca21fee455f2aa347fdb750b9fd1d))

## [1.31.9](https://github.com/jm33-m0/emp3r0r/compare/v1.31.8...v1.31.9) (2023-09-20)


### Bug Fixes

* [#253](https://github.com/jm33-m0/emp3r0r/issues/253) ([2ebb6f4](https://github.com/jm33-m0/emp3r0r/commit/2ebb6f42434b38cc458fa6b2a7ec1a72ec3c18ce))
* [#254](https://github.com/jm33-m0/emp3r0r/issues/254) ([a9f3674](https://github.com/jm33-m0/emp3r0r/commit/a9f36743fcc4c2c8e5085f9318c335280eb361fd))

## [1.31.8](https://github.com/jm33-m0/emp3r0r/compare/v1.31.7...v1.31.8) (2023-09-07)


### Bug Fixes

* [#250](https://github.com/jm33-m0/emp3r0r/issues/250)  `fork` not supported on `arm64` ([d962876](https://github.com/jm33-m0/emp3r0r/commit/d9628769f889c0ab8848f60daaf2c8b3065d0465))

## [1.31.7](https://github.com/jm33-m0/emp3r0r/compare/v1.31.6...v1.31.7) (2023-09-07)


### Bug Fixes

* [#250](https://github.com/jm33-m0/emp3r0r/issues/250) ([99b2fb0](https://github.com/jm33-m0/emp3r0r/commit/99b2fb04bb33a0c4f62ac7a8d6dc08192259a0da))

## [1.31.6](https://github.com/jm33-m0/emp3r0r/compare/v1.31.5...v1.31.6) (2023-09-03)


### Bug Fixes

* handle AES decryption panic ([48e362e](https://github.com/jm33-m0/emp3r0r/commit/48e362ef7de8c5d9a9c5bf80f2160921708ab059))

## [1.31.5](https://github.com/jm33-m0/emp3r0r/compare/v1.31.4...v1.31.5) (2023-08-10)


### Bug Fixes

* [#246](https://github.com/jm33-m0/emp3r0r/issues/246) ([da2bfd1](https://github.com/jm33-m0/emp3r0r/commit/da2bfd11729a729e8d4925862ab9b947c9795356))

## [1.31.4](https://github.com/jm33-m0/emp3r0r/compare/v1.31.3...v1.31.4) (2023-08-04)


### Bug Fixes

* `run_as_daemon` should always be enabled ([11a3979](https://github.com/jm33-m0/emp3r0r/commit/11a39793e16564ced29907bf5439ebca723177fd))
* loader.so should return error for non-`amd64` ([4170414](https://github.com/jm33-m0/emp3r0r/commit/41704149f3a511dda9beea668dc04968d7a9aa9c))

## [1.31.3](https://github.com/jm33-m0/emp3r0r/compare/v1.31.2...v1.31.3) (2023-08-04)


### Bug Fixes

* do not delay when started by loader.so ([ca596e9](https://github.com/jm33-m0/emp3r0r/commit/ca596e91ac4b8286bb9e7e0763b1deb785eae09e))

## [1.31.2](https://github.com/jm33-m0/emp3r0r/compare/v1.31.1...v1.31.2) (2023-08-03)


### Bug Fixes

* do not attemp to hide without root ([b69f6b1](https://github.com/jm33-m0/emp3r0r/commit/b69f6b116edce85c6185b33ba578c4e43361f8e4))
* loader.so unable to find exe due to malformed path name ([eec2dcc](https://github.com/jm33-m0/emp3r0r/commit/eec2dcc05adecdb89bcb9321b2a4df0778dc95f6))
* sometimes CA cert is not added to agent config ([a003cd0](https://github.com/jm33-m0/emp3r0r/commit/a003cd07de64f9f22ebd8ddd49b3fcfdb88802d4))
* use `bash` shell when started by loader.so ([d12bda5](https://github.com/jm33-m0/emp3r0r/commit/d12bda599bf01994ca2fd2e612511fb6b0a3fb8e))

## [1.31.1](https://github.com/jm33-m0/emp3r0r/compare/v1.31.0...v1.31.1) (2023-08-02)


### Bug Fixes

* `VERBOSE=true` not working ([b7894c4](https://github.com/jm33-m0/emp3r0r/commit/b7894c463e7a178ebc6b8cc51f116a4e0afa594d))
* auto-updating hide_pid list ([7a2d822](https://github.com/jm33-m0/emp3r0r/commit/7a2d8227f23a81558f82c345a5f1e4ceeb21d5b9))
* be silent when started by loader.so ([4113d3d](https://github.com/jm33-m0/emp3r0r/commit/4113d3d675669be21fa5d3c7a54523f36ffd6d6a))
* do not overwrite backup ([ef0b058](https://github.com/jm33-m0/emp3r0r/commit/ef0b05808e7f7cfaac51ceeb41575dadbcdad0dd))
* hidden_pids list gets overwritten ([fbf7c9c](https://github.com/jm33-m0/emp3r0r/commit/fbf7c9c7b0963611d20b66481d8ad46b5337c0d0))
* sort hidden_pids list ([a63dcef](https://github.com/jm33-m0/emp3r0r/commit/a63dcef6cd3db73d09d5d4a2e431221aafdae808))
* unable to read config when started by loader.so ([9074fc4](https://github.com/jm33-m0/emp3r0r/commit/9074fc4ddc8ea90851acdad8833f0007a9cc92b2))

## [1.31.0](https://github.com/jm33-m0/emp3r0r/compare/v1.30.5...v1.31.0) (2023-08-02)


### Features

* hide PIDs and files using loader.so ([c54c5f5](https://github.com/jm33-m0/emp3r0r/commit/c54c5f53522c5c93270c5189d6f54d30ee9a050c))

## [1.30.5](https://github.com/jm33-m0/emp3r0r/compare/v1.30.4...v1.30.5) (2023-07-19)


### Bug Fixes

* [#236](https://github.com/jm33-m0/emp3r0r/issues/236) ([84e1fda](https://github.com/jm33-m0/emp3r0r/commit/84e1fdacb0320d7c83cec7dea1a604749919c82f))
* `label` by tag not working ([131d84e](https://github.com/jm33-m0/emp3r0r/commit/131d84e1f1aa2e888978adaedd6876b61cd9e2ce))
* UUID is all zero for Windows ([fd487d6](https://github.com/jm33-m0/emp3r0r/commit/fd487d615c60b65b98b7c62f12994d497c24b9ff))

## [1.30.4](https://github.com/jm33-m0/emp3r0r/compare/v1.30.3...v1.30.4) (2023-07-15)


### Bug Fixes

* add option to uninstall ([e1a4e0d](https://github.com/jm33-m0/emp3r0r/commit/e1a4e0d92aa9a7a9727bf0b5df741869e959c301))

## [1.30.3](https://github.com/jm33-m0/emp3r0r/compare/v1.30.2...v1.30.3) (2023-07-12)


### Bug Fixes

* check if an ELF is static ([d574330](https://github.com/jm33-m0/emp3r0r/commit/d574330c7d212a634de1e24ac29702a4df2e26cd))
* module unpack using xz ([177eaa2](https://github.com/jm33-m0/emp3r0r/commit/177eaa2d6a70a62ad9055c9f925a71b03afc7eb2))
* pack modules with xz, reduce size even more ([955b6bd](https://github.com/jm33-m0/emp3r0r/commit/955b6bdabef121266befe952e0b3e143b6273a58))
* patch static ELFs and `patchelf` itself ([286ddfb](https://github.com/jm33-m0/emp3r0r/commit/286ddfbabd076e91b398d02429a10a5fe5d34d2f))

## [1.30.2](https://github.com/jm33-m0/emp3r0r/compare/v1.30.1...v1.30.2) (2023-07-12)


### Bug Fixes

* run path error ([773ee53](https://github.com/jm33-m0/emp3r0r/commit/773ee530f3a24868e964a56adff5e347d50da2b9))

## [1.30.1](https://github.com/jm33-m0/emp3r0r/compare/v1.30.0...v1.30.1) (2023-07-11)


### Bug Fixes

* add `libexpat.so.1` as python needs it ([76a9acf](https://github.com/jm33-m0/emp3r0r/commit/76a9acf00c2391735313f57808a85673bd2a22fb))
* too many python files, and libs not added ([7757097](https://github.com/jm33-m0/emp3r0r/commit/775709722719ed84ccee0604a6be624a27d94416))

## [1.30.0](https://github.com/jm33-m0/emp3r0r/compare/v1.29.7...v1.30.0) (2023-07-11)


### Features

* reduce size of `vaccine` ([c560dbb](https://github.com/jm33-m0/emp3r0r/commit/c560dbb5c93bfda418b8e07baf514c788b4919de))

## [1.29.7](https://github.com/jm33-m0/emp3r0r/compare/v1.29.6...v1.29.7) (2023-06-30)


### Bug Fixes

* agent wait queue ([f4e45f7](https://github.com/jm33-m0/emp3r0r/commit/f4e45f7bd5b6d482c57fade7bfe3404773fc3255))

## [1.29.6](https://github.com/jm33-m0/emp3r0r/compare/v1.29.5...v1.29.6) (2023-06-30)


### Bug Fixes

* `IsAgentAlive` stuck ([2792bf3](https://github.com/jm33-m0/emp3r0r/commit/2792bf33124d573f95c91a73e27a6aa9e69a389e))
* `profiles` persistence method ([6321b3c](https://github.com/jm33-m0/emp3r0r/commit/6321b3cc27e3efe32442a68b67fadd89b67dae24))
* guadian shellcode unable to start agent ([9b81317](https://github.com/jm33-m0/emp3r0r/commit/9b81317e8fedce49f562ea348386d07cd1121159))
* guardian shellcode: restore original binary ([a07b280](https://github.com/jm33-m0/emp3r0r/commit/a07b28012cf82690a5000ab48ad7a1de990a51e4))
* let user choose to inject existing lib/sc ([47fd9e6](https://github.com/jm33-m0/emp3r0r/commit/47fd9e6439a99b4d01bb24ccf859a101b5b7cfd7))
* optimize `profiles` persistence ([963ba13](https://github.com/jm33-m0/emp3r0r/commit/963ba13e04f0c1a8f97d985f25c82bb9443dfbcf))
* remove `injector` in `get_persistence`, etc ([f7e04b1](https://github.com/jm33-m0/emp3r0r/commit/f7e04b17e307c936108cc1820fe0f1bf4991b585))

## [1.29.5](https://github.com/jm33-m0/emp3r0r/compare/v1.29.4...v1.29.5) (2023-06-28)


### Bug Fixes

* change process name affects loader.so ([83c1109](https://github.com/jm33-m0/emp3r0r/commit/83c1109adea87c8732d4bdfd637b6e13c193096b))
* ~elf loader unable to run emp3r0r~ ([d534359](https://github.com/jm33-m0/emp3r0r/commit/d534359bfff417a04053ef0499f46d6a6d14c0e0))
* outdated loader.so ([3ee239e](https://github.com/jm33-m0/emp3r0r/commit/3ee239e560aeac6f7a07f20d719f05a939f98d05))
* process renaming can't start new process ([2ca3fc1](https://github.com/jm33-m0/emp3r0r/commit/2ca3fc1c0714fceb28da7712ec6f6c51034a12ee))

## [1.29.4](https://github.com/jm33-m0/emp3r0r/compare/v1.29.3...v1.29.4) (2023-06-27)


### Bug Fixes

* build issue ([67eb322](https://github.com/jm33-m0/emp3r0r/commit/67eb3222530d94b80340efae2b0db50f1d82031e))
* loader.so extraction error ([03fde3d](https://github.com/jm33-m0/emp3r0r/commit/03fde3d51e2c0c00631f35fc21ed17a7820c9d6f))

## [1.29.3](https://github.com/jm33-m0/emp3r0r/compare/v1.29.2...v1.29.3) (2023-06-27)


### Bug Fixes

* `inject_loader` fails to launch agent ([77c445b](https://github.com/jm33-m0/emp3r0r/commit/77c445b6b07d0a2cacda0c672388d0830a620d70))

## [1.29.2](https://github.com/jm33-m0/emp3r0r/compare/v1.29.1...v1.29.2) (2023-06-26)


### Bug Fixes

* `get_persistence`: fix `profiles` method ([7a1858e](https://github.com/jm33-m0/emp3r0r/commit/7a1858e4a848d97153d0d4bc80ab6638f1dcd4cf))
* add help to `get_persistence` ([a5a9879](https://github.com/jm33-m0/emp3r0r/commit/a5a98794c0955f44568e9e68806db123b49603de))
* argv spoofing only works with long argv0 ([0f322bf](https://github.com/jm33-m0/emp3r0r/commit/0f322bf12f3a9ff84f311bc46964ba29303ce3a9))
* cleanup queue when there are too many waiting ([3933766](https://github.com/jm33-m0/emp3r0r/commit/39337667d7557ab4905ae63947626635e479c3ff))
* daemonizing issues (argv modification fails) ([d005862](https://github.com/jm33-m0/emp3r0r/commit/d00586280befe80f007b749bb68362018a1848e8))
* don't install to all locations at once ([87f1ebb](https://github.com/jm33-m0/emp3r0r/commit/87f1ebb7db801139dabf73cf2381a07fc7b6ebe3))
* inject_loader ([694fa31](https://github.com/jm33-m0/emp3r0r/commit/694fa31148a970dc14859fbeb8386a5749ab4ca2))

## [1.29.1](https://github.com/jm33-m0/emp3r0r/compare/v1.29.0...v1.29.1) (2023-06-25)


### Bug Fixes

* [#219](https://github.com/jm33-m0/emp3r0r/issues/219) ([f0b414a](https://github.com/jm33-m0/emp3r0r/commit/f0b414a2147037ab3c248934dc5c3c5b9904949a))
* `get_persistence` causes unalias error ([43dc8ee](https://github.com/jm33-m0/emp3r0r/commit/43dc8ee181e5194b07454b466a48c49abae2b494))
* `get_persistence` result readability issue ([438289f](https://github.com/jm33-m0/emp3r0r/commit/438289f6cb7081860f26a76ade301b48a1e76d03))
* damonize and be silent when started by persistence script ([e14f3eb](https://github.com/jm33-m0/emp3r0r/commit/e14f3eb94f81ddb24fbb3e268c5f7dfc66a9630e))

## [1.29.0](https://github.com/jm33-m0/emp3r0r/compare/v1.28.0...v1.29.0) (2023-06-21)


### Features

* switch to utls to defeat JA3 fingerprinting ([b9bf54f](https://github.com/jm33-m0/emp3r0r/commit/b9bf54f1a33389d64e658c73e04af5a4412b1da6))

## [1.28.0](https://github.com/jm33-m0/emp3r0r/compare/v1.27.3...v1.28.0) (2023-05-24)


### Features

* add `ssh_harvester` ([6a557e1](https://github.com/jm33-m0/emp3r0r/commit/6a557e192c45799a6b0f84795119e3fd18e4ac9b))
* inject arbitrary shared lib ([f4a0c1c](https://github.com/jm33-m0/emp3r0r/commit/f4a0c1c85ddec6f47c5f64dda5183c6dac1edba0))


### Bug Fixes

* unable to log to file ([55c4f7b](https://github.com/jm33-m0/emp3r0r/commit/55c4f7b84d3ef7708fc2e144a87c2d92605cf2b0))

## [1.27.3](https://github.com/jm33-m0/emp3r0r/compare/v1.27.2...v1.27.3) (2023-05-15)


### Bug Fixes

* [#210](https://github.com/jm33-m0/emp3r0r/issues/210) ([f926d83](https://github.com/jm33-m0/emp3r0r/commit/f926d830ed1719827e1a3c0f919d5d12a05f791d))
* BlackArch PKGBUILD ([5cc5d1f](https://github.com/jm33-m0/emp3r0r/commit/5cc5d1ff1a42cd92d85307abc098e4fb7e931128))

## [1.27.2](https://github.com/jm33-m0/emp3r0r/compare/v1.27.1...v1.27.2) (2023-05-05)


### Bug Fixes

* improve `upgrade_agent` ([a80f30b](https://github.com/jm33-m0/emp3r0r/commit/a80f30b626c155735a9fcdda3c1a01dd06ce9474))
* panic: nil ref when UDP port_fwd session dies ([0cd3746](https://github.com/jm33-m0/emp3r0r/commit/0cd3746e9eba734f0e87d7a84e9317142f9036a3))

## [1.27.1](https://github.com/jm33-m0/emp3r0r/compare/v1.27.0...v1.27.1) (2023-05-04)


### Bug Fixes

* UDP forwarding ([c462312](https://github.com/jm33-m0/emp3r0r/commit/c462312a1db770707b103ae5419d4a6cd6e5ba2c))

## [1.27.0](https://github.com/jm33-m0/emp3r0r/compare/v1.26.8...v1.27.0) (2023-05-04)


### Features

* UDP port mapping ([c2b6b32](https://github.com/jm33-m0/emp3r0r/commit/c2b6b32b2f0b8ee19d7ea7fce5fe199fdac94711))


### Bug Fixes

* command time msg should exclude built-in cmds ([e6a5d2d](https://github.com/jm33-m0/emp3r0r/commit/e6a5d2d3c34beb5330522f5dfe2419d862b413dd))
* portfwd timeout implementation ([b22e91d](https://github.com/jm33-m0/emp3r0r/commit/b22e91d7898530197bdd1602235d5728ef6ea3da))
* reduce noisy logging for debug level 2 ([56b3d9a](https://github.com/jm33-m0/emp3r0r/commit/56b3d9a94a02c957d796d43d1e04e4456742373f))
* remove redundant cmdline args ([a2ee4f1](https://github.com/jm33-m0/emp3r0r/commit/a2ee4f1251185c700df0556091fc88555cd5ae0f))
* timeout connections for socks5 proxy ([1b4c6ca](https://github.com/jm33-m0/emp3r0r/commit/1b4c6ca3ddac4d03206cbb536af9cec8a7e6f76c))

## [1.26.8](https://github.com/jm33-m0/emp3r0r/compare/v1.26.7...v1.26.8) (2023-04-21)


### Bug Fixes

* `use` command should show more info about the selected module ([e04dc5b](https://github.com/jm33-m0/emp3r0r/commit/e04dc5b246b822fc9fb8b9b5ab82ba4d15d37275))
* agent side SOCKS5 server lacks authentication ([67cba96](https://github.com/jm33-m0/emp3r0r/commit/67cba9613a95b1181de439adfbad39eb9b9f9f20))

## [1.26.7](https://github.com/jm33-m0/emp3r0r/compare/v1.26.6...v1.26.7) (2023-04-19)


### Bug Fixes

* [#201](https://github.com/jm33-m0/emp3r0r/issues/201), use winpty to support ConPTY shell on all Windows versions ([dfc54c0](https://github.com/jm33-m0/emp3r0r/commit/dfc54c0a11f8a976928b2e39f8369f954d688e2d))
* upgrade dependencies ([069484a](https://github.com/jm33-m0/emp3r0r/commit/069484a7faf0b21f3e8d83717367115cc6ef87f9))

## [1.26.6](https://github.com/jm33-m0/emp3r0r/compare/v1.26.5...v1.26.6) (2023-04-18)


### Bug Fixes

* [#203](https://github.com/jm33-m0/emp3r0r/issues/203) ([972664a](https://github.com/jm33-m0/emp3r0r/commit/972664ae8597ea346e2f44525d4a17b14c144fdd))

## [1.26.5](https://github.com/jm33-m0/emp3r0r/compare/v1.26.4...v1.26.5) (2023-04-18)


### Bug Fixes

* auto-resize console buffer on elvsh start, to match C2 terminal size ([71167e4](https://github.com/jm33-m0/emp3r0r/commit/71167e487ecccbf84522b73c430e4271a5afc847))
* improve `PATH` handling on Windows/Linux ([dfcf572](https://github.com/jm33-m0/emp3r0r/commit/dfcf572e07e0fd0b2fd5150959ec819be7a529e9))

## [1.26.4](https://github.com/jm33-m0/emp3r0r/compare/v1.26.3...v1.26.4) (2023-04-14)


### Bug Fixes

* [#199](https://github.com/jm33-m0/emp3r0r/issues/199) ([7591681](https://github.com/jm33-m0/emp3r0r/commit/759168139a5e25b2d2199182d14f22c5b4041e13))

## [1.26.3](https://github.com/jm33-m0/emp3r0r/compare/v1.26.2...v1.26.3) (2023-04-14)


### Bug Fixes

* [#192](https://github.com/jm33-m0/emp3r0r/issues/192) ([18e2a9b](https://github.com/jm33-m0/emp3r0r/commit/18e2a9bc1866efb5cc39e3951a0a45d68a4863b0))

## [1.26.2](https://github.com/jm33-m0/emp3r0r/compare/v1.26.1...v1.26.2) (2023-04-14)


### Bug Fixes

* [#196](https://github.com/jm33-m0/emp3r0r/issues/196) ([1ec35ca](https://github.com/jm33-m0/emp3r0r/commit/1ec35ca4f6e3d54800832199e2bb3b8b806f93b4))
* `elvsh` shell cant start due to missing agent binary ([c090e08](https://github.com/jm33-m0/emp3r0r/commit/c090e0854e4ccfeb462728e54dd1ef73e186ad50))
* DownloadViaCC has racing issue ([0d96ca8](https://github.com/jm33-m0/emp3r0r/commit/0d96ca811de660b54a2379f8fa165984b29e18c6))
* timeout kill should not happen with cmds like `get` ([9ddf659](https://github.com/jm33-m0/emp3r0r/commit/9ddf659d9989ecfd6b01329253987ab3ca88b384))

## [1.26.1](https://github.com/jm33-m0/emp3r0r/compare/v1.26.0...v1.26.1) (2023-04-13)


### Bug Fixes

* mips builds missing ([dd9eed5](https://github.com/jm33-m0/emp3r0r/commit/dd9eed5922f0620069a2dc467f4a5e6075fa93b6))
* multi-arch build, cc crash on start ([fb04c2c](https://github.com/jm33-m0/emp3r0r/commit/fb04c2cbe6b5800477bfa1c9a1bcfe40aa39951b))

## [1.26.0](https://github.com/jm33-m0/emp3r0r/compare/v1.25.8...v1.26.0) (2023-04-13)


### Features

* multi-arch support ([40bc0fe](https://github.com/jm33-m0/emp3r0r/commit/40bc0fe9e123eac5842a32c6af5d3facc56c0ebf))


### Bug Fixes

* confusion on `reverse_proxy` feature, see [#190](https://github.com/jm33-m0/emp3r0r/issues/190) ([b6425f0](https://github.com/jm33-m0/emp3r0r/commit/b6425f0b7a4dea1ac25b46055325c6f32d620c49))
* incomplete file download percentage ([b4e120e](https://github.com/jm33-m0/emp3r0r/commit/b4e120ef7650bbb2fa90df2aa617df8a48a06eea))
* syscall.Dup2 not ready for multi-arch support ([13826d2](https://github.com/jm33-m0/emp3r0r/commit/13826d23693bcf3d445a6c96cd49f956ae71df90))

## [1.25.8](https://github.com/jm33-m0/emp3r0r/compare/v1.25.7...v1.25.8) (2023-04-04)


### Bug Fixes

* file downloading progress might stuck at 100% when connection is interrupted ([37eabb2](https://github.com/jm33-m0/emp3r0r/commit/37eabb2c51df158c5b42de37f90403e6be6cf912))

## [1.25.7](https://github.com/jm33-m0/emp3r0r/compare/v1.25.6...v1.25.7) (2023-04-03)


### Bug Fixes

* disable console resizing for windows due to bugs ([19e7a88](https://github.com/jm33-m0/emp3r0r/commit/19e7a887e9ae91c1690e895f7cfcab184afbad76))
* improve file downloading feature ([2ec7f02](https://github.com/jm33-m0/emp3r0r/commit/2ec7f0233868f181dbd819bd91323934475e4039))

## [1.25.6](https://github.com/jm33-m0/emp3r0r/compare/v1.25.5...v1.25.6) (2023-04-02)


### Bug Fixes

* c2 server no longer needs to be manually restarted when new c2 name is added ([8d9a81b](https://github.com/jm33-m0/emp3r0r/commit/8d9a81b8c7caebe44530f950e53182a353796955))

## [1.25.5](https://github.com/jm33-m0/emp3r0r/compare/v1.25.4...v1.25.5) (2023-03-31)


### Bug Fixes

* disable sysinfo warnings ([e7e07a2](https://github.com/jm33-m0/emp3r0r/commit/e7e07a2c86fcb84c500b0575f8551bf0ee907d88))
* log requests to stager HTTP server ([787344d](https://github.com/jm33-m0/emp3r0r/commit/787344ddf4f14a222f8437b60b08572285bf0be4))
* no need to remove in python stager ([09c1c03](https://github.com/jm33-m0/emp3r0r/commit/09c1c03f464961673d3a06ab82e16c5491fe8144))
* unable to read mac addr in kvm machines (virtio NIC) ([58ed35a](https://github.com/jm33-m0/emp3r0r/commit/58ed35a412a6357d949963333ae332584d871ea1))

## [1.25.4](https://github.com/jm33-m0/emp3r0r/compare/v1.25.3...v1.25.4) (2023-03-30)


### Bug Fixes

* disable agent logging by default ([687230c](https://github.com/jm33-m0/emp3r0r/commit/687230c260b958c05e214f6452ccec6dbd00dc77))
* run modules without specifying target ([8630a24](https://github.com/jm33-m0/emp3r0r/commit/8630a24adce278853cff2a01657c19c37dfb4c58))
* stager content should be copied to clipboard automatically when possible ([0425501](https://github.com/jm33-m0/emp3r0r/commit/04255015505c7e8c17b84c92758b0d95db6a985f))

## [1.25.3](https://github.com/jm33-m0/emp3r0r/compare/v1.25.2...v1.25.3) (2023-03-30)


### Bug Fixes

* existing stager HTTP server should shutdown gracefully when a new stager is requested ([54005d8](https://github.com/jm33-m0/emp3r0r/commit/54005d866dd53e85c799ce9c0008dba1b34e568e))
* python stager not working and not secure ([4962cd8](https://github.com/jm33-m0/emp3r0r/commit/4962cd872a27fbd1dedb5484ec9d7b697d398241))

## [1.25.2](https://github.com/jm33-m0/emp3r0r/compare/v1.25.1...v1.25.2) (2023-03-29)


### Bug Fixes

* cleanup work for stager, python2, obfuscate agent binary ([e91f583](https://github.com/jm33-m0/emp3r0r/commit/e91f5832007be6c5c1cc391aa52e172f652fdfc6))
* dynamic prompt string not available after `CliAsk` or `CliYesNo` ([85e6eba](https://github.com/jm33-m0/emp3r0r/commit/85e6ebac773f692bc91cfad7111ff6c575098475))
* write back agent binary so elvsh can still start ([9966d53](https://github.com/jm33-m0/emp3r0r/commit/9966d531e4373fe11a5a3525892588a3159748ca))

## [1.25.1](https://github.com/jm33-m0/emp3r0r/compare/v1.25.0...v1.25.1) (2023-03-24)


### Bug Fixes

* `linux/bash` stager serving: incorrect path ([0f1b33f](https://github.com/jm33-m0/emp3r0r/commit/0f1b33fb1ebdd4d416e2d0759f407ac8cfeba72f))
* linux agent proc renaming when using `linux/bash` stager ([575777f](https://github.com/jm33-m0/emp3r0r/commit/575777f1a51c22492fd61b5307680f59bf218b45))

## [1.25.0](https://github.com/jm33-m0/emp3r0r/compare/v1.24.2...v1.25.0) (2023-03-24)


### Features

* implement basic stager (linux/bash) ([9f4f9ba](https://github.com/jm33-m0/emp3r0r/commit/9f4f9baed0e85096c9950a7fa219ab3eadeb0fb9))

## [1.24.2](https://github.com/jm33-m0/emp3r0r/compare/v1.24.1...v1.24.2) (2023-03-19)


### Bug Fixes

* agent won't run when packed by upx ([4d35ef9](https://github.com/jm33-m0/emp3r0r/commit/4d35ef9d0fef31aa2fbadbffb426319c43618997))

## [1.24.1](https://github.com/jm33-m0/emp3r0r/compare/v1.24.0...v1.24.1) (2023-03-17)


### Bug Fixes

* `elvsh` shell for windows ([e4d97d8](https://github.com/jm33-m0/emp3r0r/commit/e4d97d8f9c5cc886efa782879377d754c2f2f911))
* `PATH` env should contain `sbin` paths ([4036968](https://github.com/jm33-m0/emp3r0r/commit/40369682981190dad41e1080e568fd0fa1979a17))

## [1.24.0](https://github.com/jm33-m0/emp3r0r/compare/v1.23.6...v1.24.0) (2023-03-17)


### Features

* add elvsh as default shell ([12eba72](https://github.com/jm33-m0/emp3r0r/commit/12eba72ec21d7bb3b88b8b924a00731705d5ea51))


### Bug Fixes

* elvsh not working in ssh ([18773eb](https://github.com/jm33-m0/emp3r0r/commit/18773eb290734939e186e2505a61eca07d511d70))
* elvsh should reuse sftp port ([8d8c99d](https://github.com/jm33-m0/emp3r0r/commit/8d8c99d418484cba4e1da2c83d59c06bddb53b8b))
* elvsh: disable daemon ([96e5293](https://github.com/jm33-m0/emp3r0r/commit/96e52934d2045f0ea8460539915e65040c088baf))
* remove `vim` command in favor of `file_manager` ([6164d95](https://github.com/jm33-m0/emp3r0r/commit/6164d9599f6a750ae4c459e32898644ccd8831d7))

## [1.23.6](https://github.com/jm33-m0/emp3r0r/compare/v1.23.5...v1.23.6) (2023-03-17)


### Bug Fixes

* `interactive_shell` cmd env ([fc386ab](https://github.com/jm33-m0/emp3r0r/commit/fc386ab61ca3cad1b5f788c9c39f56363d04b6f5))
* `interactive_shell` fails to execute due to empty argv ([5b7e397](https://github.com/jm33-m0/emp3r0r/commit/5b7e397b1582ce5749ce6fee6696359153354960))
* concurrent map access in handshake thread ([1adbb47](https://github.com/jm33-m0/emp3r0r/commit/1adbb47df7200b80eceb11e9c3fd11eddfcd541d))

## [1.23.5](https://github.com/jm33-m0/emp3r0r/compare/v1.23.4...v1.23.5) (2023-03-16)


### Bug Fixes

* /bin/bash doesnt exist on some systems ([794887f](https://github.com/jm33-m0/emp3r0r/commit/794887fe8836f3cb0a1dc5570003f5014b1de91c))
* auto-modify cmdline args (linux) ([b4ca3a3](https://github.com/jm33-m0/emp3r0r/commit/b4ca3a3a06df7d0740d55845356eb8b86543943a))

## [1.23.4](https://github.com/jm33-m0/emp3r0r/compare/v1.23.3...v1.23.4) (2023-02-22)


### Bug Fixes

* embeded bash binary won't run, throws SEGV ([9fca402](https://github.com/jm33-m0/emp3r0r/commit/9fca402d7eb52a76fb67d0bfa72057e196a38486))

## [1.23.3](https://github.com/jm33-m0/emp3r0r/compare/v1.23.2...v1.23.3) (2023-02-22)


### Bug Fixes

* [#152](https://github.com/jm33-m0/emp3r0r/issues/152): drop extension name for Linux agent binary ([79dfba2](https://github.com/jm33-m0/emp3r0r/commit/79dfba272360069ac4305891857b71b7c6655343))
* agent fails to connect on first try ([1675de9](https://github.com/jm33-m0/emp3r0r/commit/1675de98b715d603ca40d54ab26bb3d2bfe6f896))
* report arp cache ([658c823](https://github.com/jm33-m0/emp3r0r/commit/658c823f0ca19582a1d0d934e57e7979c76743e3))

## [1.23.2](https://github.com/jm33-m0/emp3r0r/compare/v1.23.1...v1.23.2) (2023-02-20)


### Bug Fixes

* go get -u ([8c90301](https://github.com/jm33-m0/emp3r0r/commit/8c903010692512a0c9d740d9cc4436428ba5b90d))

## [1.23.1](https://github.com/jm33-m0/emp3r0r/compare/v1.23.0...v1.23.1) (2023-02-20)


### Bug Fixes

* remove packer ([713e725](https://github.com/jm33-m0/emp3r0r/commit/713e725d0bcb285ac69efcc17c1ecee113569dcd))
* upgrade deps ([441b978](https://github.com/jm33-m0/emp3r0r/commit/441b978d39ee40a783ee275d3028d31a34287473))

## [1.23.0](https://github.com/jm33-m0/emp3r0r/compare/v1.22.3...v1.23.0) (2023-01-04)


### Features

* ditch static magic string for packer ([f7edcc6](https://github.com/jm33-m0/emp3r0r/commit/f7edcc6c6eecc3cb5d9ff2dbffc3b739efefe029))
* improve agent binary structure ([fd76e5c](https://github.com/jm33-m0/emp3r0r/commit/fd76e5cd3bb8efcd2b017ca24ada5d432e070b0c))
* pack agent binary by default (linux) ([4811229](https://github.com/jm33-m0/emp3r0r/commit/4811229b8ca75a13c6ba691e0a432d4bdbad03aa))
* use AES-CBC mode to support tiny-AES ([72c4cea](https://github.com/jm33-m0/emp3r0r/commit/72c4cea4bf2d6dc178b55531c58f6f632a717765))


### Bug Fixes

* make bash command line look normal ([2315c96](https://github.com/jm33-m0/emp3r0r/commit/2315c96f006619fc110dce5dae534ac541aeb426))
* xz should be single-threaded ([4056da9](https://github.com/jm33-m0/emp3r0r/commit/4056da9a55277a9190a97da4641f43e33cf44ae5))

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
