package transport

import (
	"strings"
	"testing"
)

func TestIPinCIDR(t *testing.T) {
	// Single-host /32 range.
	ips := IPinCIDR("", "192.168.1.5/32")
	if len(ips) != 1 || ips[0] != "192.168.1.5" {
		t.Fatalf("/32 enumeration = %v, want [192.168.1.5]", ips)
	}

	// Small /30 range with port.
	ips = IPinCIDR("8080", "10.0.0.0/30")
	want := []string{"10.0.0.0:8080", "10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"}
	if len(ips) != len(want) {
		t.Fatalf("/30 enumeration = %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("/30 enumeration[%d] = %q, want %q (all: %v)", i, ips[i], want[i], ips)
		}
	}

	// Result must be textual, not raw 4-byte binary garbage (regression: the
	// old implementation returned string(net.IP) which embedded NUL bytes).
	for _, ip := range ips {
		if strings.ContainsRune(ip, 0x00) {
			t.Fatalf("enumerated address contains NUL byte: %q", ip)
		}
		if strings.Contains(ip, ":") == false {
			t.Fatalf("expected host:port form, got %q", ip)
		}
	}
}

func TestIPinCIDR_InvalidAndNonV4(t *testing.T) {
	if got := IPinCIDR("80", "not-a-cidr"); got != nil {
		t.Fatalf("invalid CIDR should return nil, got %v", got)
	}
	// IPv6 is not supported by the uint32 arithmetic; must return nil instead
	// of producing garbage or hanging.
	if got := IPinCIDR("80", "fd00::/120"); got != nil {
		t.Fatalf("IPv6 CIDR should return nil, got %d entries", len(got))
	}
}

func TestIPinCIDR_NoOverflowOnWideRange(t *testing.T) {
	// The old implementation looped from i:=start; i<=finish; i++ and
	// overflowed (infinite loop) when finish == 0xffffffff (0.0.0.0/0).
	// It must now terminate and cap the result.
	ips := IPinCIDR("80", "0.0.0.0/0")
	if len(ips) == 0 || len(ips) > int(maxCIDREnumeration) {
		t.Fatalf("wide CIDR returned %d entries (cap %d)", len(ips), maxCIDREnumeration)
	}
	if ips[0] != "0.0.0.0:80" {
		t.Fatalf("first entry = %q, want 0.0.0.0:80", ips[0])
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in      string
		wantLen int
		wantErr bool
	}{
		{"10.0.0.1", 1, false},
		{"10.0.0.1:443", 1, false},
		{"192.168.1.0/30:8080", 4, false},
		{"192.168.1.0/30", 4, false},
		{"", 0, true},
		{"not a target", 1, false}, // hostnames pass through
		{"1.2.3.4:notaport", 0, true},
		{"1.2.3.4:0", 0, true},
		{"1.2.3.4:65536", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q): expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if len(got) != tc.wantLen {
			t.Errorf("ParseTarget(%q): got %d entries %v, want %d", tc.in, len(got), got, tc.wantLen)
		}
	}
}
