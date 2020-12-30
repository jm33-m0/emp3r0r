package agent

import (
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"time"
)

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

// Copy copy file from src to dst
func Copy(src, dst string) error {
	in, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, in, 0755)
}

// RandInt random int between given interval
func RandInt(min, max int) int {
	seed := rand.NewSource(time.Now().UTC().Unix())
	return min + rand.New(seed).Intn(max-min)
}
