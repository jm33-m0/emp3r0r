package memmod

import (
	"errors"
	"fmt"
)

// MaxExportArguments is the maximum number of machine-word arguments accepted
// by CallExportWithArgs on every supported platform. It covers the first five
// integer argument registers of the amd64/arm64 C ABIs.
const MaxExportArguments = 5

// ErrGoExportArgumentsUnsupported reports that CallExportWithArgs was used on
// a Go c-shared image. Use CallExport for its zero-argument exports instead.
var ErrGoExportArgumentsUnsupported = errors.New("memmod: CallExportWithArgs is not supported for Go c-shared images")

func validateExportArguments(args []uintptr) error {
	if len(args) > MaxExportArguments {
		return fmt.Errorf("memmod: export call has %d arguments; maximum is %d", len(args), MaxExportArguments)
	}
	return nil
}
