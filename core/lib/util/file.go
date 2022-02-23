package util

import (
	"bufio"
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	mathRand "math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mholt/archiver/v4"
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
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Printf("LsPath: %v", err)
		return
	}

	// parse
	var dents []Dentry
	for _, f := range files {
		var dent Dentry
		dent.Name = f.Name()
		dent.Date = f.ModTime().String()
		dent.Ftype = "file"
		if f.IsDir() {
			dent.Ftype = "dir"
		}
		dent.Permission = f.Mode().String()
		dent.Size = fmt.Sprintf("%d bytes", f.Size())
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
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// RemoveDupsFromArray remove duplicated items from string slice
func RemoveDupsFromArray(array []string) (result []string) {
	m := make(map[string]bool)
	for _, item := range array {
		if _, ok := m[item]; !ok {
			m[item] = true
		}
	}

	for item := range m {
		result = append(result, item)
	}
	return result
}

// AppendToFile append text to a file
func AppendToFile(filename string, text string) (err error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
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
	in, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	if IsFileExist(dst) {
		err = os.RemoveAll(dst)
		if err != nil {
			log.Printf("Copy: %s exists and cannot be removed", dst)
		}
	}

	return ioutil.WriteFile(dst, in, 0755)
}

// RandInt random int between given interval
func RandInt(min, max int) int {
	// if we get nonsense values
	// give them random int anyway
	if min > max ||
		min < 0 ||
		max < 0 {
		min = RandInt(0, 100)
		max = min + RandInt(0, 100)
	}

	var b [8]byte
	_, err := crypto_rand.Read(b[:])
	if err != nil {
		log.Println("cannot seed math/rand package with cryptographically secure random number generator")
		log.Println("falling back to math/rand with time seed")
		return rand.New(rand.NewSource(time.Now().UnixNano())).Intn(max-min) + min
	}
	rand.Seed(int64(binary.LittleEndian.Uint64(b[:])))
	return min + rand.Intn(max-min)
}

// RandStr random string
func RandStr(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	mathRand.Seed(time.Now().Unix())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mathRand.Intn(len(letters))]
	}
	return string(b)
}

// FileBaseName /path/to/foo -> foo
func FileBaseName(filepath string) (filename string) {
	// we only need the filename
	filepathSplit := strings.Split(filepath, "/")
	filename = filepathSplit[len(filepathSplit)-1]
	return
}

// FileAllocate allocate n bytes for a file, will delete the target file if already exists
func FileAllocate(filepath string, n int64) (err error) {
	if IsFileExist(filepath) {
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

func TarBz2(dir, outfile string) error {
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
	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	// we can use the CompressedArchive type to gzip a tarball
	// (compression is not required; you could use Tar directly)
	format := archiver.CompressedArchive{
		Compression: archiver.Bz2{},
		Archival:    archiver.Tar{},
	}

	// create the archive
	err = format.Archive(context.Background(), out, files)
	if err != nil {
		return err
	}
	return nil
}

func ReverseString(s string) string {
	rns := []rune(s) // convert to rune
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		// swap the letters of the string,
		// like first with last and so on.
		rns[i], rns[j] = rns[j], rns[i]
	}

	// return the reversed string.
	return string(rns)
}
