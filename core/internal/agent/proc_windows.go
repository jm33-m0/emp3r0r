//go:build windows
// +build windows

package agent

func crossPlatformSetProcName(string) {
}

func ProcUID(int) string {
	return "-1"
}

func HidePIDs() error {
	return nil
}
