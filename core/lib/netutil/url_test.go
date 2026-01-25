package netutil

import (
	"testing"
)

func TestJoinURL(t *testing.T) {
	testCases := []struct {
		base     string
		paths    []string
		expected string
	}{
		{
			base:     "https://127.0.0.1:42933",
			paths:    []string{"api", "msg"},
			expected: "https://127.0.0.1:42933/api/msg",
		},
		{
			base:     "https://127.0.0.1:42933/",
			paths:    []string{"api", "msg"},
			expected: "https://127.0.0.1:42933/api/msg",
		},
		{
			base:     "https://127.0.0.1:42933",
			paths:    []string{"/api/", "/msg/"},
			expected: "https://127.0.0.1:42933/api/msg",
		},
		{
			base:     "https://127.0.0.1:42933/",
			paths:    []string{"/api/", "/msg/"},
			expected: "https://127.0.0.1:42933/api/msg",
		},
		{
			base:     "http://example.com/base",
			paths:    []string{"path"},
			expected: "http://example.com/base/path",
		},
	}

	for _, tc := range testCases {
		got := JoinURL(tc.base, tc.paths...)
		if got != tc.expected {
			t.Errorf("JoinURL(%q, %q) = %q, want %q", tc.base, tc.paths, got, tc.expected)
		}
	}
}
