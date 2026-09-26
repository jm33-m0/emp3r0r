package coffloader

import "testing"

// TestPackCoffArgsWireTokens covers the cross-platform COFF argument packer
// (used by the Linux in-memory loader and cmd/bofrunner). Booleans must pack
// as 0/1 for the integer wire type on every platform.
func TestPackCoffArgsWireTokens(t *testing.T) {
	cases := []struct {
		name string
		arg  CoffArg
		want string
	}{
		{"bool true", CoffArg{WireType: "i", Value: true}, "i1"},
		{"bool false", CoffArg{WireType: "i", Value: false}, "i0"},
		{"int", CoffArg{WireType: "i", Value: float64(7)}, "i7"},
		{"short", CoffArg{WireType: "s", Value: float64(3)}, "s3"},
		{"cstr", CoffArg{WireType: "z", Value: "hi"}, "zhi"},
		{"wstr", CoffArg{WireType: "Z", Value: "hi"}, "Zhi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PackCoffArgs([]CoffArg{tc.arg})
			if err != nil {
				t.Fatalf("PackCoffArgs: %v", err)
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("got %v, want [%q]", got, tc.want)
			}
		})
	}
}

func TestPackCoffArgsBinary(t *testing.T) {
	// base64 "AQID" decodes to bytes 0x01 0x02 0x03.
	got, err := PackCoffArgs([]CoffArg{{WireType: "b", Value: "AQID"}})
	if err != nil {
		t.Fatalf("PackCoffArgs binary: %v", err)
	}
	if len(got) != 1 || got[0] != "b010203" {
		t.Fatalf("binary pack = %v, want [b010203]", got)
	}
}

func TestPackCoffArgsRejectsBadInt(t *testing.T) {
	if _, err := PackCoffArgs([]CoffArg{{WireType: "i", Value: "not-a-number"}}); err == nil {
		t.Fatal("expected error for non-numeric int argument")
	}
}
