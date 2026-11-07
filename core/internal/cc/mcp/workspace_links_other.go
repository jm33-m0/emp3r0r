//go:build !unix

package mcp

import "os"

func hasMultipleLinks(os.FileInfo) bool { return false }

func openRead(path string) (*os.File, error) { return os.Open(path) }
