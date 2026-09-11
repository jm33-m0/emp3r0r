package util

import (
	crand "crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
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
	isQuoted := strings.Contains(cmd, "'") && strings.Count(cmd, "'")%2 == 0 && !strings.Contains(cmd, "\\")
	isEscaped := strings.Contains(cmd, "\\")
	isDoubleQuoted := strings.Contains(cmd, "\"") && strings.Count(cmd, "\"")%2 == 0

	// UUIDs act as collision-free placeholders while we protect escaped
	// spaces/tabs from the quote-aware parser below.
	space := uuid.NewString()
	tab := uuid.NewString()

	if isEscaped && (isQuoted || isDoubleQuoted) {
		cmd = strings.ReplaceAll(cmd, "\\ ", space)
		cmd = strings.ReplaceAll(cmd, "\\t", tab)
		parsedCmd = parseQuotedCmd(cmd)
		for n, arg := range parsedCmd {
			parsedCmd[n] = strings.ReplaceAll(strings.ReplaceAll(arg, space, " "), tab, "\t")
		}
		return parsedCmd
	}

	if isEscaped {
		return parseEscapedCmd(cmd, space, tab)
	}

	if isQuoted || isDoubleQuoted {
		return parseQuotedCmd(cmd)
	}

	return strings.Fields(cmd)
}

func parseEscapedCmd(cmd, space, tab string) (parsedCmd []string) {
	temp := strings.ReplaceAll(cmd, "\\ ", space)
	temp = strings.ReplaceAll(temp, "\\t", tab)
	parsedCmd = strings.Fields(temp)
	for n, arg := range parsedCmd {
		parsedCmd[n] = strings.ReplaceAll(strings.ReplaceAll(arg, space, " "), tab, "\t")
	}
	return parsedCmd
}

func parseQuotedCmd(cmd string) (parsedCmd []string) {
	cmd = strings.ReplaceAll(cmd, "'", `"`) // use double quotes
	r := csv.NewReader(strings.NewReader(cmd))
	r.Comma = ' ' // space
	r.LazyQuotes = true
	fields, err := r.Read()
	if err != nil {
		logging.Debugf("ParseCmd: %v", err)
		return parsedCmd
	}
	for _, f := range fields {
		parsedCmd = append(parsedCmd, strings.TrimSpace(f))
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

// Truncate shortens s to at most max bytes, appending an ellipsis when it
// actually truncates. It counts whole runes, so a multi-byte character is
// never split into invalid UTF-8. max is the total byte budget including the
// ellipsis; a max of 3 or less yields only the ellipsis that fits, and a
// non-positive max yields "".
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	// A string cannot need truncation if its byte length is within budget,
	// since rune count is always <= byte count.
	if len(s) <= max {
		return s
	}

	const ellipsis = "..."
	if max <= len(ellipsis) {
		return ellipsis[:max]
	}

	// Fill max-ellipsis bytes on rune boundaries; the remainder is the suffix.
	limit := max - len(ellipsis)
	var b strings.Builder
	b.Grow(max)
	used := 0
	for _, r := range s {
		w := utf8.RuneLen(r)
		if used+w > limit {
			break
		}
		b.WriteRune(r)
		used += w
	}
	b.WriteString(ellipsis)
	return b.String()
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
