# Changelog

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
