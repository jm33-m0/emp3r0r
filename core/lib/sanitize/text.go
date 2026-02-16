package sanitize

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI strips ANSI escape codes and removes non-printable/binary data.
//
// If binary/control data is found, it appends a hex dump of the stripped data.
func StripANSI(str string) string {
	stripped := ansiRegexp.ReplaceAllString(str, "")

	var builder strings.Builder
	var strippedBuilder strings.Builder
	hasBinary := false

	for i := 0; i < len(stripped); {
		r, width := utf8.DecodeRuneInString(stripped[i:])
		if r == utf8.RuneError && width == 1 {
			hasBinary = true
			strippedBuilder.WriteByte(stripped[i])
			i++
			continue
		}

		if unicode.IsGraphic(r) || unicode.IsSpace(r) {
			builder.WriteRune(r)
		} else {
			hasBinary = true
			strippedBuilder.WriteRune(r)
		}
		i += width
	}

	if hasBinary {
		data := []byte(strippedBuilder.String())
		var hexBuilder strings.Builder
		for i := 0; i < len(data); i += 16 {
			end := i + 16
			if end > len(data) {
				end = len(data)
			}
			hexBuilder.WriteString(fmt.Sprintf("%08x  % x\n", i, data[i:end]))
		}
		return fmt.Sprintf("%s\n\n[Binary data stripped]:\n%s", builder.String(), hexBuilder.String())
	}

	return builder.String()
}

// SanitizeText removes ANSI escape codes and drops non-printable/binary data.
// It preserves whitespace (including newlines) to keep multi-line output readable.
func SanitizeText(str string) string {
	stripped := ansiRegexp.ReplaceAllString(str, "")

	var builder strings.Builder
	for i := 0; i < len(stripped); {
		r, width := utf8.DecodeRuneInString(stripped[i:])
		if r == utf8.RuneError && width == 1 {
			i++
			continue
		}
		if unicode.IsGraphic(r) || unicode.IsSpace(r) {
			builder.WriteRune(r)
		}
		i += width
	}

	return builder.String()
}

// SanitizeOneLine sanitizes text and normalizes it into a single line.
// It collapses all whitespace (including newlines/tabs) into single spaces.
func SanitizeOneLine(str string) string {
	return strings.Join(strings.Fields(SanitizeText(str)), " ")
}
