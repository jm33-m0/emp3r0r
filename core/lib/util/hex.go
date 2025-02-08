package util

import (
	"fmt"
	"os"
	"unicode"
)

const (
	bytesPerLine   = 16          // Number of bytes per line
	maxFileSize    = 1024 * 1024 // 1MB limit
	truncateLimit  = 4096        // Limit displayed output (e.g., first 4KB)
	textCheckLimit = 512         // Check first 512 bytes to determine if it's a text file
)

// isTextFile checks if the file is likely a text file by scanning the first few bytes.
func isTextFile(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buffer := make([]byte, textCheckLimit)
	n, err := file.Read(buffer)
	if err != nil {
		return false, err
	}

	nonPrintableCount := 0
	for i := 0; i < n; i++ {
		if buffer[i] == 0 || (!unicode.IsPrint(rune(buffer[i])) && !unicode.IsSpace(rune(buffer[i]))) {
			nonPrintableCount++
		}
	}

	return float64(nonPrintableCount)/float64(n) < 0.1, nil
}

// DumpFile returns a hex dump or text of the given file.
func DumpFile(filename string) (string, error) {
	isText, err := isTextFile(filename)
	if err != nil {
		return "", err
	}

	if isText {
		return readTextFile(filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return "", err
	}

	if fileInfo.Size() > maxFileSize {
		LogDebug("Warning: File exceeds limit. Output truncated.\n")
	}

	offset := 0
	buffer := make([]byte, bytesPerLine)
	bytesRead := 0
	result := ""

	for {
		if bytesRead >= truncateLimit {
			result += "Output truncated.\n"
			break
		}

		n, err := file.Read(buffer)
		if n == 0 {
			break
		}

		// Append offset
		result += fmt.Sprintf("%08x: ", offset)

		// Append hex bytes
		for i := 0; i < bytesPerLine; i++ {
			if i < n {
				result += fmt.Sprintf("%02x ", buffer[i])
			} else {
				result += "   " // Align output for short lines
			}
			if i == 7 {
				result += " "
			}
		}

		result += " "

		// Append ASCII representation
		for i := 0; i < n; i++ {
			if buffer[i] >= 32 && buffer[i] <= 126 {
				result += fmt.Sprintf("%c", buffer[i])
			} else {
				result += "."
			}
		}

		result += "\n"
		offset += n
		bytesRead += n

		if err != nil {
			break
		}
	}

	return result, nil
}

// readTextFile returns the content of a text file as a string.
func readTextFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buffer := make([]byte, truncateLimit)
	n, err := file.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}
