package sanitize

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// stripEscapeSeq removes one complete terminal escape sequence starting at
// the ESC byte at s[i]. It handles:
//   - CSI: ESC [ params... final(0x40-0x7e)   e.g. SGR colors, cursor moves
//   - OSC: ESC ] ... BEL(0x07) | ESC \         e.g. title/hyperlink injection
//   - 2-char sequences: ESC <letter>            e.g. ESC c (RIS reset)
//
// It returns the new index i and true when a sequence was consumed. Only
// stripping the ESC byte (as the legacy SGR-only regexp did) left the payload
// of OSC/CSI injections — `]0;id;cat /etc/shadow` or `[H` — visible in the
// operator console/log.
func stripEscapeSeq(s []byte, i int) (int, bool) {
	if s[i] != 0x1b || i+1 >= len(s) {
		return i, false
	}
	switch s[i+1] {
	case '[': // CSI
		j := i + 2
		for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
			j++
		}
		if j < len(s) {
			j++ // consume final byte
		}
		return j, true
	case ']': // OSC: terminated by BEL or ESC \
		j := i + 2
		for j < len(s) {
			if s[j] == 0x07 {
				j++
				break
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				j += 2
				break
			}
			j++
		}
		return j, true
	default: // two-char control: ESC c, ESC 7, ESC D ...
		if s[i+1] <= 0x1f || s[i+1] == 0x7f {
			return i + 2, true
		}
		return i + 1, true // lone ESC followed by a printable: drop just the ESC
	}
}

// stripTerminalEscapes removes all CSI/OSC/two-char escape sequences and lone
// ESC bytes from b.
func stripTerminalEscapes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] == 0x1b {
			if next, ok := stripEscapeSeq(b, i); ok {
				i = next
				continue
			}
			i++ // lone ESC: drop it
			continue
		}
		out = append(out, b[i])
		i++
	}
	return out
}

// StripANSI strips ANSI escape codes and removes non-printable/binary data.
//
// If binary/control data is found, it appends a hex dump of the stripped data.
func StripANSI(str string) string {
	stripped := string(stripTerminalEscapes([]byte(str)))

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
	stripped := string(stripTerminalEscapes([]byte(str)))

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
