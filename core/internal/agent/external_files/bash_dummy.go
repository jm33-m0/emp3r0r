//go:build !linux
// +build !linux

package external_files

// ExtractBashRC extract embedded bashrc and configure our bash shell
func ExtractBashRC() error {
	return nil
}
