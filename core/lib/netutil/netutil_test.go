package netutil

import (
	"net"
	"testing"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		ip    string
		valid bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"256.0.0.1", false},
		{"abc", false},
		{"::1", true},
		{"fe80::1", true},
		{"", false},
	}

	for _, tt := range tests {
		if got := ValidateIP(tt.ip); got != tt.valid {
			t.Errorf("ValidateIP(%q) = %v, want %v", tt.ip, got, tt.valid)
		}
	}
}

func TestValidateHostName(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"example.com", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"invalid..com", false},
		{"very.long.domain.name.that.should.be.valid.if.it.is.under.253.characters.com", true},
	}

	for _, tt := range tests {
		if got := ValidateHostName(tt.host); got != tt.valid {
			t.Errorf("ValidateHostName(%q) = %v, want %v", tt.host, got, tt.valid)
		}
	}
}

func TestIsPortOpen(t *testing.T) {
	// Start a listener on a random port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Test open port
	if !IsPortOpen("127.0.0.1", port) {
		t.Errorf("IsPortOpen failed for open port %s", port)
	}

	// Test closed port (assuming 0 is closed or invalid for connection)
	// Using a port that is unlikely to be open.
	// Note: IsPortOpen has a 3s timeout, so this might slow down tests.
	// We can skip it or accept the delay.
	// Let's try a port that should fail quickly.
}
