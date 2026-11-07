//go:build unix

package opsec

import "os"

func isGroupOrWorldWritable(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 != 0
}
