//go:build linux
// +build linux

package agentutils

import (
	"os"
)

// TouchFile restores the modification and change times of a file
func TouchFile(file string) error {
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

// CopyFileTimes copies timestamps from source file to destination file
// This function synchronizes the modification and access times
func CopyFileTimes(srcFile, dstFile string) error {
	// Get the source file timestamps
	srcFileInfo, err := os.Stat(srcFile)
	if err != nil {
		return err
	}
	modTime := srcFileInfo.ModTime()
	// For access time, we use the same as modification time
	// since many filesystems don't track access time precisely
	atime := srcFileInfo.ModTime()

	// Apply the timestamps to the destination file
	return os.Chtimes(dstFile, atime, modTime)
}
