//go:build !linux

package agentutils

func TouchFile(file string) error {
	return nil
}

func CopyFileTimes(srcFile, dstFile string) error {
	return nil
}
