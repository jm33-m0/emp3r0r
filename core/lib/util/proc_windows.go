//go:build windows
// +build windows

package util

// Dummy implementation for windows
func SetProcName(string) {
}

func ProcUID(int) string {
	return "-1"
}

func HidePIDs() error {
	return nil
}
