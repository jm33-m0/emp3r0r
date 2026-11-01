package util

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Compress compresses data using gzip
func Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress decompresses gzip data
// MaxDecompressedBytes bounds a gzip payload from a remote agent, peer, or
// C2. The largest module image the loaders accept is 64 MiB; allow no more.
const MaxDecompressedBytes int64 = 64 << 20

// DecompressLimit decompresses data and rejects output larger than limit
// instead of allocating it first. A negative or zero limit is rejected.
func DecompressLimit(data []byte, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("invalid decompression limit: %d", limit)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("decompressed data exceeds %d bytes", limit)
	}
	return out, nil
}

func Decompress(data []byte) ([]byte, error) {
	return DecompressLimit(data, MaxDecompressedBytes)
}

// Unarchive unarchives a tarball to a directory
func Unarchive(tarball, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		localName, err := SecureLocalPath(header.Name)
		if err != nil {
			return fmt.Errorf("invalid file path %s: %w", header.Name, err)
		}
		target := filepath.Join(dst, localName)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}

// TarArchive tar a directory to tar.gz
func TarArchive(dir, outfile string) error {
	f, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := gzip.NewWriter(f)
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	dirInfo, err := os.Stat(dir)
	if err != nil {
		return err
	}
	isSingleFile := !dirInfo.IsDir()

	return filepath.Walk(dir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}

		var rel string
		if isSingleFile {
			rel = filepath.Base(file)
		} else {
			var errRel error
			rel, errRel = filepath.Rel(dir, file)
			if errRel != nil {
				return errRel
			}
		}
		header.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !fi.IsDir() {
			data, err := os.Open(file)
			if err != nil {
				return err
			}
			defer data.Close()
			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}
		return nil
	})
}
