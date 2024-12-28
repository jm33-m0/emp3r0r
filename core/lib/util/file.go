package util

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		info, statErr := f.Info()
		if statErr != nil {
			log.Printf("LsPath: %v", statErr)
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
	_, statErr := os.Stat(path)
	return !os.IsNotExist(statErr)
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

// IsDirWritable check if a directory is writable
func IsDirWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return false
	}
	// Check if the current user can write to the directory
	testFile := filepath.Join(path, fmt.Sprintf("%s", RandMD5String()))
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

// GetWritablePaths get all writable paths in a directory up to a given depth
func GetWritablePaths(root_path string, depth int) ([]string, error) {
	if depth < 0 {
		return nil, fmt.Errorf("Invalid depth: %d", depth)
	}

	var writablePaths []string
	var searchPaths func(path string, currentDepth int) error

	searchPaths = func(path string, currentDepth int) error {
		if currentDepth > depth {
			return nil
		}

		files, err := os.ReadDir(path)
		if err != nil {
			log.Printf("Skipping unreadable directory %s: %v", path, err)
			return nil
		}

		for _, file := range files {
			fullPath := filepath.Join(path, file.Name())
			if file.IsDir() {
				if IsDirWritable(fullPath) {
					writablePaths = append(writablePaths, fullPath)
				}
				if err := searchPaths(fullPath, currentDepth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := searchPaths(root_path, 0); err != nil {
		return nil, err
	}

	if len(writablePaths) == 0 {
		return nil, fmt.Errorf("No writable paths found in %s", root_path)
	}

	return writablePaths, nil
}
