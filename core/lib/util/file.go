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
	"github.com/jm33-m0/arc/v2"
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

// LsPath ls path and return a json
func LsPath(path string) (string, error) {
	parse_fileInfo := func(info os.FileInfo) (dent Dentry) {
		dent.Name = info.Name()
		dent.Date = info.ModTime().String()
		dent.Ftype = "file"
		dent.Permission = info.Mode().String()
		dent.Size = fmt.Sprintf("%d bytes", info.Size())
		return dent
	}
	// if it's a file, return its info
	if IsFileExist(path) {
		info, statErr := os.Stat(path)
		if statErr != nil {
			logging.Debugf("LsPath: %v", statErr)
			return "", statErr
		}
		dents := []Dentry{parse_fileInfo(info)}
		jsonData, err := cbor.Marshal(dents)
		if err != nil {
			logging.Debugf("LsPath: %v", err)
			return "", err
		}
		return string(jsonData), nil
	}

	// parse disk files
	files, err := os.ReadDir(path)
	if err != nil {
		logging.Debugf("LsPath: %v", err)
		// Don't return error yet, we might have memory files
	}

	// parse
	var dents []Dentry

	// Add memory files that are in this directory
	// Clean path
	path = filepath.Clean(path)
	MemFileLock.RLock()
	for memPath, data := range MemFileMap {
		memDir := filepath.Dir(memPath)
		if memDir == path {
			dents = append(dents, Dentry{
				Name:       filepath.Base(memPath),
				Ftype:      "file (mem)",
				Size:       fmt.Sprintf("%d bytes", len(data)),
				Date:       "N/A", // or keep track of creation time?
				Permission: "-rw-------",
			})
		}
	}
	MemFileLock.RUnlock()

	for _, f := range files {
		info, statErr := f.Info()
		if statErr != nil {
			logging.Debugf("LsPath: %v", statErr)
			continue
		}
		// If memory file overlaps with disk file, we show both? Or memory overrides?
		// WriteFileAgent (memory strategy) deletes disk file.
		// So they shouldn't overlap usually.
		dents = append(dents, parse_fileInfo(info))
	}

	if len(dents) == 0 && err != nil {
		return "", err
	}

	// json
	jsonData, err := cbor.Marshal(dents)
	return string(jsonData), err
}

// IsCommandExist check if an executable is in $PATH
func IsCommandExist(exe string) bool {
	_, err := exec.LookPath(exe)
	return err == nil
}

// IsFileExist check if a file exists
func IsFileExist(path string) bool {
	// check memory first
	MemFileLock.RLock()
	// Check for strict mem:// prefix or just key existence
	_, inMem := MemFileMap[path]
	if !inMem && strings.HasPrefix(path, "mem://") {
		// If strict mem protocol is used, we only check keys.
		// If not found, it's not there.
		MemFileLock.RUnlock()
		return false
	}
	MemFileLock.RUnlock()
	if inMem {
		return true
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
	// check memory first
	MemFileLock.RLock()
	_, inMem := MemFileMap[path]
	if !inMem && strings.HasPrefix(path, "mem://") {
		MemFileLock.RUnlock()
		return false
	}
	MemFileLock.RUnlock()
	if inMem {
		return true
	}

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

		targetPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			return os.MkdirAll(targetPath, d.Type().Perm())
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
	if strings.HasPrefix(path, "mem://") {
		return filepath.Base(path)
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
			return
		}
	}
	f, err := os.Create(filepath)
	if err != nil {
		return
	}
	defer f.Close()
	_ = f.Truncate(n)

	return
}

// FileSize calc file size
func FileSize(path string) (size int64) {
	MemFileLock.RLock()
	if data, ok := MemFileMap[path]; ok {
		MemFileLock.RUnlock()
		return int64(len(data))
	}
	MemFileLock.RUnlock()

	// If it was meant to be a memory file but didn't exist, return 0
	if strings.HasPrefix(path, "mem://") {
		return 0
	}

	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	size = fi.Size()
	return
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

// RemoveFileAgent removes a file (wrapper for os.RemoveAll with pattern support)
func RemoveFileAgent(path string) error {
	path = ApplyFilePattern(path)

	// memory
	MemFileLock.Lock()
	if _, ok := MemFileMap[path]; ok {
		delete(MemFileMap, path)
		MemFileLock.Unlock()
		logging.Debugf("Agent: Removed memory file %s", path)
		return nil
	}
	MemFileLock.Unlock()

	if strings.HasPrefix(path, "mem://") {
		return fmt.Errorf("memory file %s not found", path)
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

	// Try memory copy first (if src is memory file)
	// We optimize by checking MemFileMap directly or using IsFileExist
	// But to differentiate Dir vs File for mixed usage, we need care.
	// For "mem://", it is always a file.
	if strings.HasPrefix(src, "mem://") {
		return copyFileAgent(src, dst)
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		// If not on disk, it might be an implicit memory file (not starting with mem://)?
		// IsFileExist said yes, but os.Stat says no -> Must be Memory.
		// So treat as file.
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

	// if destination is a directory
	// we need to be careful with pattern here.
	// If dst is a dir, we join with basename.
	// WriteFileAgent will apply pattern to the FULL path.
	// So we pass the path as intended.

	f, err := os.Stat(dst)
	if err == nil {
		if f.IsDir() {
			dst = filepath.Join(dst, filepath.Base(src))
		}
	}

	// WriteFileAgent handles MkdirAll and ApplyFilePattern
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
			// creating dir: MkdirAll.
			// WriteFileAgent doesn't create empty dirs.
			// We should perhaps hook Mkdir?
			// The user said "every file". Dirs are files.
			// For now, let's just use os.MkdirAll for dirs as placeholders.
			targetPath = ApplyFilePattern(targetPath)
			return os.MkdirAll(targetPath, d.Type().Perm())
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
		if strings.HasPrefix(k, "mem://") {
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
	// Apply pattern
	filename = ApplyFilePattern(filename)

	// Force memory strategy for mem:// paths
	if strings.HasPrefix(filename, "mem://") {
		strategy = StorageMemory
	}

	// Encrypt data BEFORE storage (Disk or Memory)
	// This ensures memory dumps don't show plaintext files
	if len(fileCryptoKey) > 0 {
		var err error
		data, err = crypto.AES_GCM_Encrypt(fileCryptoKey, data)
		if err != nil {
			return fmt.Errorf("WriteFileAgent encrypt: %v", err)
		}
	}

	// In-memory storage decision based on available memory
	limit := int64(MemFileSizeLimit)

	// Check available physical memory
	freeMem := GetMemAvailable()
	if freeMem > 0 {
		dynamicLimit := freeMem / 10

		const MaxMemPerFile = 100 * 1024 * 1024 // 100MB
		if dynamicLimit > MaxMemPerFile {
			dynamicLimit = MaxMemPerFile
		}

		limit = dynamicLimit
	}

	// Decide storage
	saveToMemory := false
	switch strategy {
	case StorageMemory:
		saveToMemory = true
	case StorageDisk:
		saveToMemory = false
	case StorageAuto:
		if int64(len(data)) <= limit {
			saveToMemory = true
		}
	}

	if saveToMemory {
		MemFileLock.Lock()

		// We store ENCRYPTED data in memory now
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		MemFileMap[filename] = dataCopy
		MemFileLock.Unlock()

		// Remove from disk if it exists there, to enforce "memory only"
		if IsExist(filename) && !strings.HasPrefix(filename, "mem://") {
			os.Remove(filename)
		}

		logging.Debugf("Agent: Wrote %d bytes (encrypted) to memory: %s (limit: %d)", len(data), filename, limit)
		return nil
	}

	// Fail if we wanted memory but couldn't
	if strategy == StorageMemory {
		return fmt.Errorf("SaveFileAgent: failed to save %s to memory (limit: %d bytes)", filename, limit)
	}

	// If implicit memory (StorageAuto) fell through to here, it means we must write to disk.
	// But if path is explicitly mem://, we should have caught it above?
	// Yes, mem:// sets strategy=StorageMemory, so it returns error instead of falling through.

	// For disk storage
	// Ensure we clean up memory if it was there
	MemFileLock.Lock()
	delete(MemFileMap, filename)
	MemFileLock.Unlock()

	logging.Debugf("Agent: Writing %d bytes (encrypted) to %s with permissions %o", len(data), filename, perm)

	// ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return fmt.Errorf("WriteFileAgent mkdir %s: %v", filepath.Dir(filename), err)
	}

	// Currently just wraps os.WriteFile
	return os.WriteFile(filename, data, perm)
}

// ReadFileAgent reads a file from the agent's filesystem
func ReadFileAgent(filename string) ([]byte, error) {
	// Apply pattern
	filename = ApplyFilePattern(filename)

	logging.Debugf("Agent: Reading file %s", filename)

	var data []byte
	var err error
	inMemory := false

	// Check memory first
	MemFileLock.RLock()
	if memData, ok := MemFileMap[filename]; ok {
		// return copy
		data = make([]byte, len(memData))
		copy(data, memData)
		inMemory = true
	}
	MemFileLock.RUnlock()

	if inMemory {
		logging.Debugf("Agent: Read %d bytes from memory: %s", len(data), filename)
	} else {
		data, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
	}

	// File decryption after reading
	// Note: If it was executable, we wrote it plaintext. We need to know if we should decrypt.
	// How do we know?
	// 1. We can try to decrypt. If it fails (AES GCM tag check), assume plaintext?
	// 2. Or we trust that if it's in MemFileMap, it IS encrypted.
	//    If it's on Disk, it MIGHT be encrypted.

	// Issue: If we force plaintext for executables on disk, ReadFileAgent needs to know not to decrypt them.
	// But ReadFileAgent doesn't take 'perm' or 'isExecutable'.
	// Heuristic: Try Decrypt. If error, return original data?
	// GCM Open will fail if not valid.
	// BUT, what if plaintext coincidentally looks like valid GCM? Unlikely with Salt/Nonce.
	// Let's use Try-Decrypt strategy.

	if len(fileCryptoKey) > 0 {
		decrypted, err := crypto.AES_GCM_Decrypt(fileCryptoKey, data)
		if err == nil {
			data = decrypted
		} else {
			// If decryption fails, it might be a plaintext file (e.g. executable) or corruption.
			// Return as-is (Plaintext).
			// logging.Debugf("ReadFileAgent: Decrypt failed for %s, returning raw: %v", filename, err)
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
func AppendTextToFileAgent(filename string, text string) error {
	return AppendToFileAgent(filename, []byte(text))
}

// UnarchiveAgent unarchives a tarball (which might be encrypted) to a directory
// It ensures that extracted files are also written using WriteFileAgent (blocking plaintext on disk)
func UnarchiveAgent(tarball, dst string) error {
	// 1. Read (and decrypt) tarball
	data, err := ReadFileAgent(tarball)
	if err != nil {
		return fmt.Errorf("read tarball: %v", err)
	}

	// 2. Decompress XZ (using arc library)
	tarData, err := arc.DecompressXz(data)
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

		// Check for Zip Slip (path traversal)
		if !filepath.IsLocal(header.Name) {
			return fmt.Errorf("unsafe tar header name: %s", header.Name)
		}
		targetPath := filepath.Join(dst, header.Name)
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
