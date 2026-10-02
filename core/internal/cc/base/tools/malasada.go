package tools

import (
	"fmt"
	"os"

	"github.com/sliverarmory/malasada"
)

// ConvertSharedObjectToShellcode converts a Linux ELF shared object into a
// malasada position-independent blob, first materializing the RELATIVE
// relocations that lld leaves out of the init array (see materializeInitArray).
func ConvertSharedObjectToShellcode(soPath, exportName string, compress bool) ([]byte, error) {
	so, err := os.ReadFile(soPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", soPath, err)
	}
	fixed, err := materializeInitArray(so)
	if err != nil {
		return nil, fmt.Errorf("materialize init array: %w", err)
	}

	// malasada takes a path, so stage the patched image in an opaque temp file.
	tmp, err := os.CreateTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(fixed); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	sc, err := malasada.ConvertSharedObject(tmpPath, exportName, compress)
	if err != nil {
		return nil, fmt.Errorf("malasada convert: %w", err)
	}
	return sc, nil
}

// MalasadaConvert2Shellcode invokes malasada from sliver armory and writes the
// resulting PIC blob next to soPath.
func MalasadaConvert2Shellcode(soPath, exportName string, enable_compression bool) error {
	scBytes, err := ConvertSharedObjectToShellcode(soPath, exportName, enable_compression)
	if err != nil {
		return fmt.Errorf("generating Linux agent shellcode: %w", err)
	}
	if err := os.WriteFile(fmt.Sprintf("%s.bin", soPath), scBytes, 0o755); err != nil {
		return fmt.Errorf("writing Linux shellcode: %w", err)
	}
	return nil
}
