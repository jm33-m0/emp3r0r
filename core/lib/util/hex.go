package util

import (
	"bytes"
	"fmt"
	"unicode"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	bytesPerLine   = 16          // Number of bytes per line
	maxFileSize    = 1024 * 1024 // 1MB limit
	truncateLimit  = 4096        // Limit displayed output (e.g., first 4KB)
	textCheckLimit = 512         // Check first 512 bytes to determine if it's a text file
)

// DumpFile returns a hex dump or text of the given file.
func DumpFile(filename string) (string, error) {
	// Check memory or disk via ReadFileAgent (handles decryption)
	data, err := ReadFileAgent(filename)
	if err != nil {
		return "", err
	}

	// Check if text
	isText := true
	checkLimit := textCheckLimit
	if len(data) < checkLimit {
		checkLimit = len(data)
	}

	// Scan first bytes
	scanner := data[:checkLimit]
	nonPrintableCount := 0
	for _, b := range scanner {
		if b == 0 || (!unicode.IsPrint(rune(b)) && !unicode.IsSpace(rune(b))) {
			nonPrintableCount++
		}
	}
	if float64(nonPrintableCount)/float64(checkLimit) > 0.1 {
		isText = false
	}

	if isText {
		if len(data) > truncateLimit {
			return string(data[:truncateLimit]) + "\n(Output truncated)", nil
		}
		return string(data), nil
	}

	if len(data) > maxFileSize {
		logging.Debugf("Warning: File exceeds limit. Output truncated.\n")
	}

	result := ""
	offset := 0
	bytesRead := 0

	for bytesRead < len(data) {
		if bytesRead >= truncateLimit {
			result += "Output truncated.\n"
			break
		}

		end := bytesRead + bytesPerLine
		if end > len(data) {
			end = len(data)
		}
		chunk := data[bytesRead:end]
		n := len(chunk)

		// Append offset
		result += fmt.Sprintf("%08x: ", offset)

		// Append hex bytes
		for i := 0; i < bytesPerLine; i++ {
			if i < n {
				result += fmt.Sprintf("%02x ", chunk[i])
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
			if chunk[i] >= 32 && chunk[i] <= 126 {
				result += fmt.Sprintf("%c", chunk[i])
			} else {
				result += "."
			}
		}

		result += "\n"
		offset += n
		bytesRead += n
	}

	return result, nil
}

// readTextFile returns the content of a text file as a string.
func readTextFile(filename string) (string, error) {
	data, err := ReadFileAgent(filename)
	if err != nil {
		return "", err
	}
	if len(data) > truncateLimit {
		return string(data[:truncateLimit]), nil
	}
	return string(data), nil
}

// isTextFile checks if the file is likely a text file by scanning the first few bytes.
func isTextFile(filename string) (bool, error) {
	data, err := ReadFileAgent(filename)
	if err != nil {
		return false, err
	}

	limit := textCheckLimit
	if len(data) < limit {
		limit = len(data)
	}

	nonPrintableCount := 0
	for i := 0; i < limit; i++ {
		if data[i] == 0 || (!unicode.IsPrint(rune(data[i])) && !unicode.IsSpace(rune(data[i]))) {
			nonPrintableCount++
		}
	}

	return float64(nonPrintableCount)/float64(limit) < 0.1, nil
}

func isPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

// AreBytesPrintable checks if the given bytes are printable.
func AreBytesPrintable(s []byte) bool {
	// Remove everything after the first null byte
	// We want a C string
	s = bytes.Split(s, []byte("\x00"))[0]
	for i := 0; i < len(s); i++ {
		if !isPrintable(s[i]) {
			return false
		}
	}
	return true
}
