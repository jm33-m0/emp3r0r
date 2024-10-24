package util

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mholt/archiver/v4"
)

const (
	dirPermissions  = 0o700 // Directory permissions
	filePermissions = 0o700 // File permissions
)

// Dentry Directory entry
type Dentry struct {
	Name       string `json:"name"`  // filename
	Ftype      string `json:"ftype"` // file/dir
	Size       string `json:"size"`  // 100
	Date       string `json:"date"`  // 2021-01-01
	Owner      string `json:"owner"` // jm33
	Permission string `json:"perm"`  // -rwxr-xr-x
}

// FileStat stat info of a file
type FileStat struct {
	Name       string `json:"name"`
	Permission string `json:"permission"`
	Checksum   string `json:"checksum"`
	Size       int64  `json:"size"`
}

// LsPath ls path and return a json
func LsPath(path string) (res string, err error) {
	files, err := os.ReadDir(path)
	if err != nil {
		log.Printf("LsPath: %v", err)
		return
	}

	// parse
	var dents []Dentry
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			log.Printf("LsPath: %v", err)
			continue
		}
		var dent Dentry
		dent.Name = info.Name()
		dent.Date = info.ModTime().String()
		dent.Ftype = "file"
		if f.IsDir() {
			dent.Ftype = "dir"
		}
		dent.Permission = info.Mode().String()
		dent.Size = fmt.Sprintf("%d bytes", info.Size())
		dents = append(dents, dent)
	}

	// json
	jsonData, err := json.Marshal(dents)
	res = string(jsonData)
	return
}

// IsCommandExist check if an executable is in $PATH
func IsCommandExist(exe string) bool {
	_, err := exec.LookPath(exe)
	return err == nil
}

// IsFileExist check if a file exists
func IsFileExist(path string) bool {
	f, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if err == nil {
		return !f.IsDir()
	}

	return true
}

// IsExist check if a path exists
func IsExist(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}

	return true
}

// IsDirExist check if a directory exists
func IsDirExist(path string) bool {
	f, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if err == nil {
		return f.IsDir()
	}

	return false
}

// RemoveItemFromArray remove string/int from slice
func RemoveItemFromArray[T string | int](to_remove T, sliceList []T) []T {
	list := []T{}
	for _, item := range sliceList {
		if item != to_remove {
			list = append(list, item)
		}
	}
	return list
}

// RemoveDupsFromArray remove duplicated string/int from slice
func RemoveDupsFromArray[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// IntArrayToStringArray convert int array to string array
func IntArrayToStringArray(arr []int) []string {
	var res []string
	for _, v := range arr {
		res = append(res, fmt.Sprintf("%d", v))
	}
	return res
}

// AppendToFile append bytes to a file
func AppendToFile(filename string, data []byte) (err error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return
	}
	return
}

// AppendTextToFile append text to a file
func AppendTextToFile(filename string, text string) (err error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return
	}
	return
}

// IsStrInFile works like grep, check if a string is in a text file
func IsStrInFile(text, filepath string) bool {
	f, err := os.Open(filepath)
	if err != nil {
		log.Printf("IsStrInFile: %v", err)
		return false
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.Contains(s.Text(), text) {
			return true
		}
	}

	return false
}

// Copy copy file from src to dst
func Copy(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// if destination is a directory
	f, err := os.Stat(dst)
	if err == nil {
		if f.IsDir() {
			dst = fmt.Sprintf("%s/%s", dst, FileBaseName(src))
		}
	}

	// if dst is a file and exists
	if IsFileExist(dst) {
		err = os.RemoveAll(dst)
		if err != nil {
			log.Printf("Copy: %s exists and cannot be removed: %v", dst, err)
		}
	}

	return os.WriteFile(dst, in, 0o755)
}

// FileBaseName extracts the base name of the file from a given path.
func FileBaseName(path string) string {
	// Use the standard library to safely get the base name
	return filepath.Base(filepath.Clean(path))
}

// FileAllocate allocate n bytes for a file, will delete the target file if already exists
func FileAllocate(filepath string, n int64) (err error) {
	if IsExist(filepath) {
		err = os.Remove(filepath)
		if err != nil {
			return
		}
	}
	f, err := os.Create(filepath)
	if err != nil {
		return
	}
	defer f.Close()
	f.Truncate(n)

	return
}

// FileSize calc file size
func FileSize(path string) (size int64) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	size = fi.Size()
	return
}

// TarXZ tar a directory to tar.xz
func TarXZ(dir, outfile string) error {
	// remove outfile
	os.RemoveAll(outfile)

	if !IsExist(dir) {
		return fmt.Errorf("%s does not exist", dir)
	}

	// map files on disk to their paths in the archive
	archive_dir_name := FileBaseName(dir)
	if dir == "." {
		archive_dir_name = ""
	}
	files, err := archiver.FilesFromDisk(nil, map[string]string{
		dir: archive_dir_name,
	})
	if err != nil {
		return err
	}

	// create the output file we'll write to
	outf, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer outf.Close()

	// we can use the CompressedArchive type to gzip a tarball
	// (compression is not required; you could use Tar directly)
	format := archiver.CompressedArchive{
		Compression: archiver.Xz{},
		Archival:    archiver.Tar{},
	}

	// create the archive
	err = format.Archive(context.Background(), outf, files)
	if err != nil {
		return err
	}
	return nil
}

func ReplaceBytesInFile(path string, old []byte, replace_with []byte) (err error) {
	file_bytes, err := os.ReadFile(path)
	if err != nil {
		return
	}

	to_write := bytes.ReplaceAll(file_bytes, old, replace_with)
	return os.WriteFile(path, to_write, 0o644)
}

// FindHolesInBinary find holes in a binary file that are big enough for a payload
func FindHolesInBinary(fdata []byte, size int64) (indexes []int64, err error) {
	// find_hole finds a hole from start
	find_hole := func(start int64) (end int64) {
		for i := start; i < int64(len(fdata)); i++ {
			if fdata[i] == 0 {
				end = i
			} else {
				break
			}
		}
		return
	}

	// find holes
	for i := int64(0); i < int64(len(fdata)); i++ {
		if fdata[i] == 0 {
			end := find_hole(i)
			// if hole is big enough
			if end-i >= size {
				indexes = append(indexes, i)
			}
			i = end
		}
	}

	return
}

// securePath ensures the path is safely relative to the target directory.
func securePath(basePath, relativePath string) (string, error) {
	// Clean and ensure the relative path does not start with an absolute marker
	relativePath = filepath.Clean("/" + relativePath)                         // Normalize path with a leading slash
	relativePath = strings.TrimPrefix(relativePath, string(os.PathSeparator)) // Remove leading separator

	// Join the cleaned relative path with the basePath
	dstPath := filepath.Join(basePath, relativePath)

	// Ensure the final destination path is within the basePath
	if !strings.HasPrefix(filepath.Clean(dstPath)+string(os.PathSeparator), filepath.Clean(basePath)+string(os.PathSeparator)) {
		return "", fmt.Errorf("illegal file path: %s", dstPath)
	}
	return dstPath, nil
}

// createDir creates a directory with predefined permissions.
func createDir(path string) error {
	if err := os.MkdirAll(path, dirPermissions); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return nil
}

// handleFile handles the extraction of a file from the archive.
func handleFile(f archiver.File, dst string) error {
	// Validate and construct the destination path
	dstPath, err := securePath(dst, f.NameInArchive)
	if err != nil {
		return err
	}

	// Ensure the parent directory exists
	if err := createDir(filepath.Dir(dstPath)); err != nil {
		return err
	}

	// Check if the file is a directory
	if f.IsDir() {
		// If it's a directory, ensure it exists
		if err := createDir(dstPath); err != nil {
			return fmt.Errorf("creating directory: %w", err)
		}
		return nil
	}

	// Open the file for reading
	reader, err := f.Open()
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer reader.Close()

	// Create the destination file
	dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY, filePermissions)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer dstFile.Close()

	// Copy the file contents
	if _, err := io.Copy(dstFile, reader); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// Unarchive unarchives a tarball to a directory using the official extraction method.
func Unarchive(tarball, dst string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return fmt.Errorf("open tarball %s: %w", tarball, err)
	}
	// Identify the format and input stream for the archive
	format, input, err := archiver.Identify(tarball, f)
	if err != nil {
		return fmt.Errorf("identify format: %w", err)
	}

	// Check if the format supports extraction
	extractor, ok := format.(archiver.Extractor)
	if !ok {
		return fmt.Errorf("unsupported format for extraction")
	}

	// Ensure the destination directory exists
	if err := createDir(dst); err != nil {
		return fmt.Errorf("creating destination directory: %w", err)
	}

	// Extract files using the official handler
	handler := func(ctx context.Context, f archiver.File) error {
		return handleFile(f, dst)
	}

	// Use the extractor to process all files in the archive
	if err := extractor.Extract(context.Background(), input, nil, handler); err != nil {
		return fmt.Errorf("extracting files: %w", err)
	}

	return nil
}
