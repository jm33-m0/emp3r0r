package detection

import (
	"strconv"
	"strings"
)

// generatedPayloadMarker is the line module build scripts print for each
// artifact they produce.
const generatedPayloadMarker = "[+] generated payload: "

// GeneratedPayload is one artifact reported by a module build.
type GeneratedPayload struct {
	Path string
	Size int64
}

// ParseGeneratedPayloads extracts the artifacts from a module build log.
// The expected line is:
//
//	[+] generated payload: <path> (<n> bytes)
func ParseGeneratedPayloads(buildLog string) []GeneratedPayload {
	var out []GeneratedPayload
	for _, line := range strings.Split(buildLog, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		payload, ok := strings.CutPrefix(line, generatedPayloadMarker)
		if !ok {
			continue
		}
		open := strings.LastIndex(payload, " (")
		close := strings.LastIndex(payload, " bytes)")
		if open < 0 || close < open {
			continue
		}
		path := strings.TrimSpace(payload[:open])
		size, err := strconv.ParseInt(strings.TrimSpace(payload[open+2:close]), 10, 64)
		if err != nil || path == "" || size <= 0 {
			continue
		}
		out = append(out, GeneratedPayload{Path: path, Size: size})
	}
	return out
}
