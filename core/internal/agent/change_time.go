//go:build linux
// +build linux

package agent

import (
	"os"
)

// RestoreFileTimes restores the modification and change times of a file
func RestoreFileTimes(file string) error {
	// Get the original file timestamps
	fileInfo, err := os.Stat(file)
	if err != nil {
		return err
	}
	modTime := fileInfo.ModTime()
	atime := fileInfo.ModTime()

	// Restore the times
	return os.Chtimes(file, atime, modTime)
}
