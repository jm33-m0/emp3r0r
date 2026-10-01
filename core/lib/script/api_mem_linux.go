//go:build linux && !android && (386 || amd64 || arm64)

package script

// memLoadPrepare is a no-op on Linux: the in-memory ELF loader does not rely on
// the Windows indirect-syscall table.
func memLoadPrepare() error {
	return nil
}
