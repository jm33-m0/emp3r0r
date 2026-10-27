package util

import "testing"

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{-1, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{9 * 1024 * 1024, "9.0 MiB"},
		{10 * 1024 * 1024, "10 MiB"},
		{120 * 1024 * 1024, "120 MiB"},
		{2 * 1024 * 1024 * 1024, "2.0 GiB"},
	}
	for _, c := range cases {
		if got := FormatBytes(c.n); got != c.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}
