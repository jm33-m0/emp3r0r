package util

import (
	"github.com/jm33-m0/arc"
)

// Unarchive unarchives a tarball to a directory
func Unarchive(tarball, dst string) error {
	return arc.Unarchive(tarball, dst)
}

// TarXZ tar a directory to tar.xz
func TarXZ(dir, outfile string) error {
	return arc.Archive(dir, outfile, arc.CompressionMap["xz"], arc.ArchivalMap["tar"])
}
