//go:build !linux
// +build !linux

package agent

// ExtractBashRC extract embedded bashrc and configure our bash shell
func ExtractBashRC() error {
	return nil
}
