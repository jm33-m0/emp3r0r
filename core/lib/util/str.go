package util

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// StripANSI strips ANSI text escape codes from a string and enforces strict
// sanitization: only unicode graphic chars and whitespace are allowed. If any
// other binary/control data is found, it appends the hex dump of the stripped
// data. Prefer SanitizeText where output amplification is a concern.
func StripANSI(str string) string {
	return sanitize.StripANSI(str)
}

// SanitizeText removes ANSI color escapes and drops non-printable/binary data.
// Unlike StripANSI, it does NOT append a hex dump when binary/control data is
// found. This is preferred for any user-facing rendering where output
// amplification is a concern.
func SanitizeText(str string) string {
	return sanitize.SanitizeText(str)
}

// SanitizeOneLine sanitizes text and normalizes it into a single line. It
// collapses all whitespace (including newlines/tabs) into single spaces.
func SanitizeOneLine(str string) string {
	return sanitize.SanitizeOneLine(str)
}

// ParseCmd splits a command line into arguments, honoring single quotes,
// double quotes and backslash escapes. The returned slice never contains
// empty tokens.
func ParseCmd(cmd string) (parsedCmd []string) {
	parsedCmd = []string{}
	var current strings.Builder
	inSingle := false
	inDouble := false
	inToken := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
				continue
			}
			if c == '\\' && i+1 < len(cmd) {
				next := cmd[i+1]
				if next == ' ' || next == '\'' {
					current.WriteByte(next)
					i++
					continue
				}
			}
			current.WriteByte(c)
		case inDouble:
			if c == '"' {
				inDouble = false
				continue
			}
			if c == '\\' && i+1 < len(cmd) {
				next := cmd[i+1]
				switch next {
				case '"', '\\', '\'', ' ':
					current.WriteByte(next)
					i++
					continue
				case 't':
					current.WriteByte('\t')
					i++
					continue
				case 'n':
					current.WriteByte('\n')
					i++
					continue
				case 'r':
					current.WriteByte('\r')
					i++
					continue
				}
			}
			current.WriteByte(c)
		default:
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				if inToken {
					if current.Len() > 0 {
						parsedCmd = append(parsedCmd, current.String())
					}
					current.Reset()
					inToken = false
				}
				continue
			}
			inToken = true
			if c == '\'' {
				inSingle = true
				continue
			}
			if c == '"' {
				inDouble = true
				continue
			}
			if c == '\\' && i+1 < len(cmd) {
				next := cmd[i+1]
				switch next {
				case ' ', '\'', '"', '\\':
					current.WriteByte(next)
					i++
					continue
				case 't':
					current.WriteByte('\t')
					i++
					continue
				case 'n':
					current.WriteByte('\n')
					i++
					continue
				case 'r':
					current.WriteByte('\r')
					i++
					continue
				}
			}
			current.WriteByte(c)
		}
	}
	if inToken && current.Len() > 0 {
		parsedCmd = append(parsedCmd, current.String())
	}
	return parsedCmd
}

// ReverseString reverses a string by runes, so multi-byte characters stay
// intact.
func ReverseString(s string) string {
	rns := []rune(s) // convert to rune
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}
	return string(rns)
}

// RandInt returns a uniformly random integer in the half-open interval
// [min, max). It draws from crypto/rand, so the result is safe for nonces,
// ports, tokens and opaque names. If max <= min the interval is empty and min
// is returned, avoiding a panic on a reversed range.
func RandInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		// A failing crypto/rand means this process has no usable entropy
		// source. Returning min is deterministic, but that is preferable to
		// silently producing a weak, attacker-predictable value from a
		// non-cryptographic fallback.
		logging.Errorf("RandInt: crypto/rand unavailable, returning min: %v", err)
		return min
	}
	return min + int(n.Int64())
}

// RandStr returns n cryptographically random ASCII letters. A non-positive n
// yields "".
func RandStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[RandInt(0, len(letters))]
	}
	return string(b)
}

// RandHexString returns 32 lowercase hex characters derived from 16
// cryptographically random bytes. It is the replacement for the former
// MD5-based helper and is suitable for opaque, unguessable names and tokens.
func RandHexString() string {
	return hex.EncodeToString(RandBytes(16))
}

// RandBytes returns n cryptographically random bytes. A non-positive n yields
// nil.
func RandBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		// As with RandInt, never fall back to a predictable source; report the
		// broken entropy source instead.
		logging.Errorf("RandBytes: crypto/rand unavailable: %v", err)
		return nil
	}
	return b
}

// HexEncode renders s as a sequence of \xNN escapes, e.g.
// "Hello" -> "\x48\x65\x6c\x6c\x6f".
func HexEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 4)
	for _, c := range s {
		fmt.Fprintf(&b, `\x%x`, c)
	}
	return b.String()
}

// ParseEnvStr parses a comma-separated list of VAR=VALUE pairs into a map.
// Whitespace around keys and values is trimmed; malformed entries without an
// '=' are ignored.
func ParseEnvStr(envStr string) (envMap map[string]string) {
	envMap = make(map[string]string)
	for _, line := range strings.Split(envStr, ",") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		envMap[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return envMap
}

// LimitString returns s truncated to at most n bytes. It is a byte-oriented
// cap intended for log lines; use Truncate when the result is shown to a user
// and must remain valid UTF-8.
func LimitString(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) > n {
		return s[:n]
	}
	return s
}

// CallStack returns the stack trace of the caller, for panic diagnostics.
func CallStack() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}
