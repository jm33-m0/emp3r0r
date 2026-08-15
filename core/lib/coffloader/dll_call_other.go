//go:build windows && !amd64 && !386

package coffloader

// callLoadAndRun is a no-op for Windows architectures without a COFFLoader
// DLL (arm/arm64). RunWindowsCOFFViaDLL rejects those architectures before
// this is reached.
func callLoadAndRun(_ uintptr, _ []byte, _ uintptr) uintptr {
	return 0
}
