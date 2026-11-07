//go:build !unix && !windows

package mcp

import "os"

func hasMultipleLinks(string, os.FileInfo) bool { return false }

func openRead(path string) (*os.File, error) { return os.Open(path) }
