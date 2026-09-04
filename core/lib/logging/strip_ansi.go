package logging

import (
	"io"
)

// stripANSICodes removes ANSI escape sequences from a byte slice so on-disk
// logs stay plain text even though the console writer in the same MultiWriter
// still receives colorized output. Without this, a log file like
// emp3r0r.log accumulates raw ESC codes (the console renderer colorizes
// module output before it is logged), which breaks tools that parse module
// output from the log (e.g. bofhound ingesting ldapsearch results: a color
// prefix glued onto a result-boundary line would make it undetectable).
//
// Covered: CSI sequences (ESC [ ... final-byte, e.g. SGR color codes) and
// lone ESC bytes. Sequences split across two Write calls are not reassembled
// (color codes are always emitted complete within one message).
func stripANSICodes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if b[i] != 0x1b { // ESC
			out = append(out, b[i])
			i++
			continue
		}
		// ESC [ params... final(0x40-0x7e)
		if i+1 < len(b) && b[i+1] == '[' {
			j := i + 2
			for j < len(b) && !(b[j] >= 0x40 && b[j] <= 0x7e) {
				j++
			}
			if j < len(b) {
				j++ // consume the final byte of the sequence
			}
			i = j
			continue
		}
		i++ // lone ESC, drop it
	}
	return out
}

// PlainFileWriter returns a writer that strips ANSI escape codes from
// everything written through it. Use it when opening an on-disk log file so
// the file stays plain text (console colors belong to the terminal only).
func PlainFileWriter(w io.Writer) io.Writer {
	return ansiStripWriter{w}
}

// ansiStripWriter strips ANSI escape codes from everything written through
// it. It wraps the log file handle, leaving the other writers (console/TTY)
// in the logger's MultiWriter untouched and still colorized.
type ansiStripWriter struct{ w io.Writer }

func (s ansiStripWriter) Write(p []byte) (int, error) {
	cleaned := stripANSICodes(p)
	if _, err := s.w.Write(cleaned); err != nil {
		return 0, err
	}
	return len(p), nil
}
