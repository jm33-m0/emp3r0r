package handler

import (
	"reflect"
	"testing"
)

func TestGetMemFileCompletions(t *testing.T) {
	files := []string{
		"mem:///file1",
		"mem:///file2",
		"mem:///dir1/file3",
		"mem:///dir1/file4",
		"mem:///dir2/subdir/file5",
	}

	tests := []struct {
		name     string
		prefix   string
		expected []string
	}{
		{
			name:   "root mem:",
			prefix: "mem:",
			expected: []string{
				"mem:",
				"/",
			},
		},
		{
			name:   "root mem:/",
			prefix: "mem:/",
			expected: []string{
				"mem:/",
				"/",
			},
		},
		{
			name:   "root mem://",
			prefix: "mem://",
			expected: []string{
				"mem://",
				"/",
			},
		},
		{
			name:   "root mem:///",
			prefix: "mem:///",
			expected: []string{
				"mem:///",
				"dir1/",
				"dir2/",
				"file1",
				"file2",
			},
		},
		{
			name:   "dir1",
			prefix: "mem:///dir1/",
			expected: []string{
				"mem:///dir1/",
				"file3",
				"file4",
			},
		},
		{
			name:   "partial dir",
			prefix: "mem:///dir", // Should match dir1 and dir2, but logic is prefix based on full string?
			// Wait, runListDir uses TrimPrefix.
			// "mem:///dir1/file3" trim "mem:///dir" -> "1/file3"
			// first seg -> "1/" (because index of / is 1)
			// So completion offers "1/"
			expected: []string{
				"mem:///dir",
				"1/",
				"2/",
			},
			// This is expected behavior for incremental completion.
		},
		{
			name:   "dir2",
			prefix: "mem:///dir2/",
			expected: []string{
				"mem:///dir2/",
				"subdir/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMemFileCompletions(tt.prefix, files)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("getMemFileCompletions(%q) = %v, want %v", tt.prefix, got, tt.expected)
			}
		})
	}
}
