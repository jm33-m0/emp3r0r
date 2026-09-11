//go:build cgo && emp3r0r_so

// This build tag selects the shared-object entrypoint (Linux .so / Windows
// DLL), where the loader resolves the exported symbol instead of a process
// entrypoint.
package main

import "C"

//export main
func main() {
	agent_main()
}
