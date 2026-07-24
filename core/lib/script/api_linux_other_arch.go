//go:build linux && !amd64 && !arm64 && !386 && !arm

package script

func registerArchSyscalls() {
	// Fallback stub for remaining architectures
}
