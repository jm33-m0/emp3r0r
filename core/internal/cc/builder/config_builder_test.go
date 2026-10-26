package builder

import "testing"

func TestC2AddressHelpers(t *testing.T) {
	if got := c2AddressHost("https://front.example.com:8443"); got != "front.example.com" {
		t.Fatalf("c2AddressHost(full URL) = %q", got)
	}
	if got := c2AddressHost("c2.example.com"); got != "c2.example.com" {
		t.Fatalf("c2AddressHost(host) = %q", got)
	}
	if got := c2BaseURL("https://front.example.com", "http", "8080"); got != "https://front.example.com" {
		t.Fatalf("c2BaseURL(explicit) = %q", got)
	}
	if got := c2BaseURL("c2.example.com", "http", "8080"); got != "http://c2.example.com:8080" {
		t.Fatalf("c2BaseURL(host) = %q", got)
	}
}
