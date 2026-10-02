Windows COFF loader is copied from [goffloader](https://github.com/chvancooten/goffloader), with some fixes.

## In-memory dependency lifetime

`RunCOFFDependency` resolves the `coffloader` DLL dependency through
`core/lib/memdeps` (`Use("coffloader", …)`); `RunWindowsCOFFViaDLL` maps
caller-supplied DLL bytes through `memdeps.Run`. In both cases the image is
unmapped before the call returns, so the DLL is never left resident in
cleartext. See [`core/lib/memdeps`](../memdeps/README.md) and the
dependency-lifetime section of `core/modules/module_development_guide.md`.
