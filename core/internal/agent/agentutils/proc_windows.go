//go:build windows
// +build windows

package agentutils

func crossPlatformSetProcName(string) {
}

func ProcUID(int) string {
	return "-1"
}

func HidePIDs() error {
	return nil
}
