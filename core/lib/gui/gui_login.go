package gui

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// operatorDefaultPort is the default C2 operator server (WireGuard) port
// used when a pasted connection command omits --operator-port.
const operatorDefaultPort = 13377

// Creds holds the WireGuard / operator parameters needed to log
// into a C2 server. They are extracted by ParseConnectionCommand from the
// connection command that the C2 server prints when it provisions operators
// (see server.generateConnectionCommands), for example:
//
//	emp3r0r client --operator-port 13377 --server-wg-key 'AbC123...==' \
//	    --server-wg-ip '10.10.10.1' --operator-wg-ip '10.10.10.2' \
//	    --operator-wg-key 'xYz789...==' --c2-host 1.2.3.4
//
// The GUI login box simply takes that whole line (as printed by the server)
// and this package turns it back into structured credentials, so the operator
// does not have to copy/paste keys around manually.
type Creds struct {
	C2Host        string `json:"c2Host"`
	OperatorPort  int    `json:"operatorPort"`
	ServerWgKey   string `json:"serverWgKey"`
	ServerWgIP    string `json:"serverWgIP"`
	OperatorWgIP  string `json:"operatorWgIP"`
	OperatorWgKey string `json:"operatorWgKey"`
}

// String renders the command back in the canonical form.
func (c *Creds) String() string {
	return fmt.Sprintf("emp3r0r client --c2-host %s --operator-port %d --server-wg-key '%s' --server-wg-ip '%s' --operator-wg-ip '%s' --operator-wg-key '%s'",
		c.C2Host, c.OperatorPort, c.ServerWgKey, c.ServerWgIP, c.OperatorWgIP, c.OperatorWgKey)
}

// splitShellWords tokenizes a command line the way a POSIX shell would, for
// the narrow subset we need: single quotes, double quotes, backslash escapes
// inside double quotes/outside quotes and whitespace separation. It exists so
// we can handle connection commands where keys/ips are wrapped in single
// quotes (the server prints them quoted).
func splitShellWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	escaped := false
	started := false

	flush := func() {
		if started {
			words = append(words, cur.String())
			cur.Reset()
			started = false
		}
	}

	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			started = true
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
			started = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			started = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			started = true
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !inSingle && !inDouble:
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if escaped {
		return nil, fmt.Errorf("trailing backslash in command")
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unbalanced quotes in command")
	}
	flush()
	return words, nil
}

// flagValue extracts the value of the first "--name" (or "--name=value")
// flag present in the words slice, skipping words[0] (the binary name).
func flagValue(words []string, name string) (string, bool) {
	want := "--" + name
	for i, w := range words {
		if w == want {
			if i+1 < len(words) {
				return words[i+1], true
			}
			return "", false
		}
		if strings.HasPrefix(w, want+"=") {
			return strings.TrimPrefix(w, want+"="), true
		}
	}
	return "", false
}

// ParseConnectionCommand parses a full `emp3r0r client ...` connection
// command (the exact line printed by the C2 server / install.py) and returns
// the WireGuard credentials required to log in.
func ParseConnectionCommand(line string) (creds Creds, err error) {
	words, err := splitShellWords(strings.TrimSpace(line))
	if err != nil {
		return creds, err
	}
	if len(words) == 0 {
		return creds, fmt.Errorf("empty connection command")
	}

	// --c2-host: remote example uses a <C2_PUBLIC_IP> placeholder.
	if v, ok := flagValue(words, "c2-host"); ok {
		creds.C2Host = strings.TrimSpace(v)
	}
	if creds.C2Host == "" {
		creds.C2Host = "127.0.0.1" // local connection by default
	}
	if strings.ContainsAny(creds.C2Host, "<>") {
		return creds, fmt.Errorf("replace the %q placeholder with the actual C2 server address", creds.C2Host)
	}

	// --operator-port (WireGuard + operator service base port)
	if v, ok := flagValue(words, "operator-port"); ok && v != "" {
		port, perr := strconv.Atoi(strings.TrimSpace(v))
		if perr != nil || port <= 0 || port > 65535 {
			return creds, fmt.Errorf("invalid --operator-port %q", v)
		}
		creds.OperatorPort = port
	}
	if creds.OperatorPort == 0 {
		creds.OperatorPort = operatorDefaultPort
	}

	// WireGuard credentials
	creds.ServerWgKey, _ = flagValue(words, "server-wg-key")
	creds.ServerWgIP, _ = flagValue(words, "server-wg-ip")
	creds.OperatorWgIP, _ = flagValue(words, "operator-wg-ip")
	creds.OperatorWgKey, _ = flagValue(words, "operator-wg-key")

	// Validation
	for name, v := range map[string]string{
		"server-wg-key":   creds.ServerWgKey,
		"server-wg-ip":    creds.ServerWgIP,
		"operator-wg-ip":  creds.OperatorWgIP,
		"operator-wg-key": creds.OperatorWgKey,
	} {
		if v == "" {
			return creds, fmt.Errorf("missing --%s in connection command", name)
		}
		if strings.ContainsAny(v, "<>'\"") {
			return creds, fmt.Errorf("--%s contains a placeholder (%q): replace it with the real value", name, v)
		}
	}
	if _, err := decodeWgKey(creds.OperatorWgKey); err != nil {
		return creds, fmt.Errorf("invalid --operator-wg-key: %v", err)
	}
	if _, err := decodeWgKey(creds.ServerWgKey); err != nil {
		return creds, fmt.Errorf("invalid --server-wg-key: %v", err)
	}

	return creds, nil
}

// decodeWgKey validates that a string is a base64-encoded 32-byte WireGuard
// key and returns the raw key bytes.
func decodeWgKey(key string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		// some tools print keys URL-encoded without padding
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(key))
	}
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %v", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected a 32-byte key, got %d bytes", len(raw))
	}
	return raw, nil
}
