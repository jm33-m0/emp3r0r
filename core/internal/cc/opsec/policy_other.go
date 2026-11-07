//go:build !unix

package opsec

import "os"

func isGroupOrWorldWritable(os.FileInfo) bool {
	return false
}
