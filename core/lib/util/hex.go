package util

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	bytesPerLine   = 16          // Number of bytes per line
	maxFileSize    = 1024 * 1024 // 1MB limit
	truncateLimit  = 4096        // Limit displayed output (e.g., first 4KB)
	textCheckLimit = 512         // Check first 512 bytes to determine if it's a text file
)

// DumpFile returns a hex dump or, for text files, the file content itself.
// Output is capped at truncateLimit bytes. Reads go through ReadFileAgent, so
// this transparently handles memfs and encrypted disk files.
func DumpFile(filename string) (string, error) {
	data, err := ReadFileAgent(filename)
	if err != nil {
		return "", err
	}

	if looksLikeText(data) {
		if len(data) > truncateLimit {
			return string(data[:truncateLimit]) + "\n(Output truncated)", nil
		}
		return string(data), nil
	}

	if len(data) > maxFileSize {
		logging.Debugf("Warning: File exceeds limit. Output truncated.\n")
	}

	// Render with a Builder: the previous implementation concatenated strings
	// in a loop, which is quadratic in the number of output lines.
	var b strings.Builder
	offset := 0
	for bytesRead := 0; bytesRead < len(data); {
		if bytesRead >= truncateLimit {
			b.WriteString("Output truncated.\n")
			break
		}

		end := bytesRead + bytesPerLine
		if end > len(data) {
			end = len(data)
		}
		chunk := data[bytesRead:end]
		n := len(chunk)

		// Offset column.
		fmt.Fprintf(&b, "%08x: ", offset)

		// Hex column, padded so the ASCII column stays aligned on short lines.
		for i := 0; i < bytesPerLine; i++ {
			if i < n {
				fmt.Fprintf(&b, "%02x ", chunk[i])
			} else {
				b.WriteString("   ")
			}
			if i == 7 {
				b.WriteByte(' ')
			}
		}
		b.WriteByte(' ')

		// Printable ASCII column.
		for i := 0; i < n; i++ {
			if chunk[i] >= 32 && chunk[i] <= 126 {
				b.WriteByte(chunk[i])
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')

		offset += n
		bytesRead += n
	}

	return b.String(), nil
}

// looksLikeText reports whether data is likely text: fewer than 10% of the
// sampled leading bytes are NUL or non-printable. The sample is capped at
// textCheckLimit bytes, and empty input is considered text.
func looksLikeText(data []byte) bool {
	limit := textCheckLimit
	if len(data) < limit {
		limit = len(data)
	}
	if limit == 0 {
		return true
	}

	nonPrintable := 0
	for _, b := range data[:limit] {
		if b == 0 || (!unicode.IsPrint(rune(b)) && !unicode.IsSpace(rune(b))) {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(limit) <= 0.1
}

// isTextFile checks if the file is likely a text file by scanning the first
// few bytes. It shares looksLikeText with DumpFile so both paths classify a
// file identically.
func isTextFile(filename string) (bool, error) {
	data, err := ReadFileAgent(filename)
	if err != nil {
		return false, err
	}
	return looksLikeText(data), nil
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
