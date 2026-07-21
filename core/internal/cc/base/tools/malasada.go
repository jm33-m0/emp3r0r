package tools

import (
	"fmt"
	"os"

	"github.com/sliverarmory/malasada"
)

// MalasadaConvert2Shellcode invokes malasada tool from sliver armory
func MalasadaConvert2Shellcode(soPath, exportName string, enable_compression bool) error {
	sc_bytes, err := malasada.ConvertSharedObject(soPath, "main", enable_compression)
	if err != nil {
		return fmt.Errorf("generating Linux agent shellcode: %v", err)
	}
	err = os.WriteFile(fmt.Sprintf("%s.bin", soPath), sc_bytes, 0o755)
	if err != nil {
		return fmt.Errorf("writing Linux shellcode: %v", err)
	}
	return nil
}
