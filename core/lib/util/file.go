package util

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

	files, err := os.ReadDir(path)
	if err != nil {
		logging.Debugf("LsPath: %v", err)
		return "", err
	}

	// parse
	var dents []Dentry
	for _, f := range files {
		info, statErr := f.Info()
		if statErr != nil {
			logging.Debugf("LsPath: %v", statErr)
			continue
		}
		dents = append(dents, parse_fileInfo(info))
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
		logging.Debugf("IsStrInFile: %v", err)
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

// Copy copy file or directory from src to dst
func Copy(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
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
func SecureLocalPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}

	localized, err := filepath.Localize(path)
	if err != nil {
		return "", fmt.Errorf("localize %q: %w", path, err)
	}

	if !filepath.IsLocal(localized) {
		return "", fmt.Errorf("unsafe path %q", localized)
	}

	return localized, nil
}

// FileBaseName extracts the base name of the file from a given path while enforcing locality.
func FileBaseName(path string) string {
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
	logging.Debugf("Agent: Removing file %s", path)
	return os.RemoveAll(path)
}

// CopyAgent copy file or directory from src to dst (Agent specific)
func CopyAgent(src, dst string) error {
	src = ApplyFilePattern(src) // Source might also follow pattern? Usually we read existing files, but if we copy internal files...
	// If src is an external file, ApplyFilePattern might break it if we assume everything has pattern.
	// But the requirement is "every file... pattern".
	// For now, let's apply it to dst. Source depends on context.
	// If we copy /bin/ls to /tmp/ls, dst should have pattern. src should not.
	// But if we copy /tmp/ls (previous step) to /tmp/ls.2, then src has pattern.
	// This ambiguity makes automatic pattern hard.
	// Assuming ApplyFilePattern is idempotent or smart?
	// For now, I will apply it to dst only, assuming src is provided "as is" by caller (caller might have applied pattern if needed).
	// dst = ApplyFilePattern(dst) -> WriteFileAgent does this!

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		return copyDirAgent(src, dst)
	}
	return copyFileAgent(src, dst)
}

func copyFileAgent(src, dst string) error {
	in, err := os.ReadFile(src)
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

// SetFileCryptoKey sets the key for file encryption
func SetFileCryptoKey(key []byte) {
	fileCryptoKey = key
}

// WriteFileAgent is a centralized file writing function for agent operations.
// This function wraps all file writing operations to allow for future modifications
// such as encryption, steganography, or other security enhancements.
func WriteFileAgent(filename string, data []byte, perm os.FileMode) error {
	// Apply pattern
	filename = ApplyFilePattern(filename)

	// File encryption before writing
	if len(fileCryptoKey) > 0 {
		var err error
		data, err = crypto.AES_GCM_Encrypt(fileCryptoKey, data)
		if err != nil {
			return fmt.Errorf("WriteFileAgent encrypt: %v", err)
		}
	}

	logging.Debugf("Agent: Writing %d bytes to %s with permissions %o", len(data), filename, perm)

	// ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return fmt.Errorf("WriteFileAgent mkdir %s: %v", filepath.Dir(filename), err)
	}

	// Currently just wraps os.WriteFile, but can be enhanced later
	return os.WriteFile(filename, data, perm)
}

// ReadFileAgent reads a file from the agent's filesystem
func ReadFileAgent(filename string) ([]byte, error) {
	// Apply pattern
	filename = ApplyFilePattern(filename)

	logging.Debugf("Agent: Reading file %s", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// File decryption after reading
	if len(fileCryptoKey) > 0 {
		decrypted, err := crypto.AES_GCM_Decrypt(fileCryptoKey, data)
		if err != nil {
			logging.Debugf("ReadFileAgent decrypt %s: %v, returning raw data", filename, err)
			return data, nil // fallback to raw data for backward compatibility or non-encrypted files
		}
		data = decrypted
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
