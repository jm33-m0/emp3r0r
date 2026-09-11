//go:build linux && amd64

package modules

import "testing"

// TestParseMapRange covers the /proc/<pid>/maps address-range parser. The
// regression this guards against is the old strings.Split(field, "-")[1] use,
// which panicked ("index out of range") on any line whose range field lacked a
// '-' separator, crashing the agent on malformed input.
func TestParseMapRange(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		want    [2]uint64
		wantErr bool
	}{
		{
			name:  "typical range",
			field: "55f8d9e0a000-55f8d9e2b000",
			want:  [2]uint64{0x55f8d9e0a000, 0x55f8d9e2b000},
		},
		{
			name:  "high canonical range",
			field: "7f1c2a3b4000-7f1c2a3b5000",
			want:  [2]uint64{0x7f1c2a3b4000, 0x7f1c2a3b5000},
		},
		{
			name:  "single byte range",
			field: "1000-1001",
			want:  [2]uint64{0x1000, 0x1001},
		},
		{
			name:    "missing separator must not panic",
			field:   "55f8d9e0a000",
			wantErr: true,
		},
		{
			name:    "multiple separators keeps first split",
			field:   "1000-2000-3000",
			wantErr: true,
		},
		{
			name:    "empty field",
			field:   "",
			wantErr: true,
		},
		{
			name:    "invalid hex start",
			field:   "zzzz-2000",
			wantErr: true,
		},
		{
			name:    "invalid hex end",
			field:   "1000-zzzz",
			wantErr: true,
		},
		{
			name:    "inverted range",
			field:   "2000-1000",
			wantErr: true,
		},
		{
			name:    "empty range",
			field:   "1000-1000",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parseMapRange(tt.field)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseMapRange(%q) = (%#x, %#x), want error", tt.field, start, end)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMapRange(%q): unexpected error: %v", tt.field, err)
			}
			if start != tt.want[0] || end != tt.want[1] {
				t.Fatalf("parseMapRange(%q) = (%#x, %#x), want (%#x, %#x)",
					tt.field, start, end, tt.want[0], tt.want[1])
			}
		})
	}
}
