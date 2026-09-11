package transport

import (
	"slices"
	"strings"
	"testing"
)

func TestSMBPipeBaseDeterministicAndUnique(t *testing.T) {
	base := smbPipeBase("password", "salt", 4000)
	if base == "" {
		t.Fatal("pipe base is empty")
	}
	if strings.ContainsAny(base, `\/: `) {
		t.Fatalf("pipe base %q contains path/space characters", base)
	}
	if got := smbPipeBase("password", "salt", 4000); got != base {
		t.Fatalf("not deterministic: %q != %q", got, base)
	}

	others := map[string]string{
		"password": smbPipeBase("other-password", "salt", 4000),
		"salt":     smbPipeBase("password", "other-salt", 4000),
		"port":     smbPipeBase("password", "salt", 4001),
	}
	for field, other := range others {
		if other == base {
			t.Fatalf("pipe base did not change when %s changed", field)
		}
	}
}

func TestParseSMBAddr(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"10.1.2.3:4000", "10.1.2.3", 4000},
		{"host.example:445", "host.example", 445},
		{"10.1.2.3", "10.1.2.3", 0},
		{"host.example", "host.example", 0},
		{"[fe80::1]:4000", "fe80::1", 4000},
		{"[fe80::1]", "fe80::1", 0},
		{"  10.0.0.1:80  ", "10.0.0.1", 80},
	}
	for _, tc := range cases {
		host, port := parseSMBAddr(tc.in)
		if host != tc.host || port != tc.port {
			t.Errorf("parseSMBAddr(%q) = (%q, %d), want (%q, %d)", tc.in, host, port, tc.host, tc.port)
		}
	}
}

func TestSMBTransportRegistered(t *testing.T) {
	if !slices.Contains(AllTransportNames(), smbTransportName) {
		t.Fatalf("transport %q not registered (have %v)", smbTransportName, AllTransportNames())
	}
	if _, ok := Transports.Load(smbTransportName); !ok {
		t.Fatalf("transport %q missing from registry", smbTransportName)
	}
}
