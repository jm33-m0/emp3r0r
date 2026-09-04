package gui

import (
	"strings"
	"testing"
)

const (
	testServerWgKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testServerWgIP   = "10.77.0.1"
	testOperatorWgIP = "10.77.0.2"
	testOpWgKey      = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
)

func TestSplitShellWords(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  []string
		fails bool
	}{
		{"plain", "a b c", []string{"a", "b", "c"}, false},
		{"single quotes", "a 'b c' d", []string{"a", "b c", "d"}, false},
		{"double quotes", "a \"b c\" d", []string{"a", "b c", "d"}, false},
		{"mixed quotes", `a 'x "y"' "p 'q'"`, []string{"a", `x "y"`, "p 'q'"}, false},
		{"backslash escape", `a b\ c`, []string{"a", "b c"}, false},
		{"empty", "   ", nil, false},
		{"unbalanced", "a 'b", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitShellWords(tc.in)
			if tc.fails {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestParseGuiConnectionCommand(t *testing.T) {
	// The exact formats the C2 server prints (server_main.go).
	local := `emp3r0r client --c2-host 127.0.0.1 --operator-port 13377 ` +
		`--server-wg-key '` + testServerWgKey + `' --server-wg-ip '` + testServerWgIP + `' ` +
		`--operator-wg-ip '` + testOperatorWgIP + `' --operator-wg-key '` + testOpWgKey + `'`

	remote := `emp3r0r client --operator-port 13377 ` +
		`--server-wg-key '` + testServerWgKey + `' --server-wg-ip '` + testServerWgIP + `' ` +
		`--operator-wg-ip '` + testOperatorWgIP + `' --operator-wg-key '` + testOpWgKey + `' ` +
		`--c2-host 8.8.8.8`

	noQuotes := "emp3r0r client --operator-port 13377 " +
		"--server-wg-key " + testServerWgKey + " --server-wg-ip " + testServerWgIP + " " +
		"--operator-wg-ip " + testOperatorWgIP + " --operator-wg-key " + testOpWgKey + " " +
		"--c2-host 1.1.1.1"

	equalsForm := "emp3r0r client --c2-host=2.2.2.2 --operator-port=13377 " +
		"--server-wg-key=" + testServerWgKey + " --server-wg-ip=" + testServerWgIP + " " +
		"--operator-wg-ip=" + testOperatorWgIP + " --operator-wg-key=" + testOpWgKey

	cases := []struct {
		name      string
		in        string
		wantC2    string
		wantPort  int
		wantError bool
	}{
		{"local quoted", local, "127.0.0.1", 13377, false},
		{"remote quoted", remote, "8.8.8.8", 13377, false},
		{"no quotes", noQuotes, "1.1.1.1", 13377, false},
		{"equals form", equalsForm, "2.2.2.2", 13377, false},
		{"c2 placeholder", `emp3r0r client --operator-port 13377 --server-wg-key '` + testServerWgKey + `' --server-wg-ip '` + testServerWgIP + `' --operator-wg-ip '` + testOperatorWgIP + `' --operator-wg-key '` + testOpWgKey + `' --c2-host <C2_PUBLIC_IP>`, "", 0, true},
		{"missing key", "emp3r0r client --c2-host 1.1.1.1 --operator-port 13377", "", 0, true},
		{"invalid key", "emp3r0r client --c2-host 1.1.1.1 --operator-port 13377 --server-wg-key short --server-wg-ip " + testServerWgIP + " --operator-wg-ip " + testOperatorWgIP + " --operator-wg-key " + testOpWgKey, "", 0, true},
		{"empty", "", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := ParseConnectionCommand(tc.in)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, got creds %+v", creds)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if creds.C2Host != tc.wantC2 {
				t.Errorf("C2Host = %q, want %q", creds.C2Host, tc.wantC2)
			}
			if creds.OperatorPort != tc.wantPort {
				t.Errorf("OperatorPort = %d, want %d", creds.OperatorPort, tc.wantPort)
			}
			if creds.ServerWgKey != testServerWgKey {
				t.Errorf("ServerWgKey not parsed correctly: %q", creds.ServerWgKey)
			}
			if creds.ServerWgIP != testServerWgIP {
				t.Errorf("ServerWgIP = %q, want %q", creds.ServerWgIP, testServerWgIP)
			}
			if creds.OperatorWgIP != testOperatorWgIP {
				t.Errorf("OperatorWgIP = %q, want %q", creds.OperatorWgIP, testOperatorWgIP)
			}
			if creds.OperatorWgKey != testOpWgKey {
				t.Errorf("OperatorWgKey not parsed correctly")
			}
			// round-trip
			if !strings.Contains(creds.String(), "--server-wg-key '"+testServerWgKey+"'") {
				t.Errorf("round-trip String() broken: %s", creds.String())
			}
		})
	}
}

func TestDecodeWgKey(t *testing.T) {
	if _, err := decodeWgKey(testServerWgKey); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := decodeWgKey("not-a-key"); err == nil {
		t.Fatal("invalid key accepted")
	}
}
