Windows COFF loader is copied from [goffloader](https://github.com/chvancooten/goffloader), with some fixes.

## Linux

`RunLinuxCOFF` resolves the `coffloader_linux` shared-object dependency through
`memdeps.Use("coffloader_linux", …)`, maps it, calls its `bof_run` export, and
unmaps it before returning. The loader source is shared with the C agent and
built by [`core/modules/coffloader_linux`](../../modules/coffloader_linux).

## In-memory dependency lifetime

`RunCOFFDependency` resolves the `coffloader` DLL dependency through
`core/lib/memdeps` (`Use("coffloader", …)`); `RunWindowsCOFFViaDLL` maps
caller-supplied DLL bytes through `memdeps.Run`. In both cases the image is
unmapped before the call returns, so the DLL is never left resident in
cleartext. See [`core/lib/memdeps`](../memdeps/README.md) and the
dependency-lifetime section of `core/modules/module_development_guide.md`.
