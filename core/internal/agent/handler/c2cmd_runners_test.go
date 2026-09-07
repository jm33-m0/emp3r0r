package handler

import (
	"reflect"
	"testing"
)

func TestGetMemFileCompletions(t *testing.T) {
	files := []string{
		"memfs:///file1",
		"memfs:///file2",
		"memfs:///dir1/file3",
		"memfs:///dir1/file4",
		"memfs:///dir2/subdir/file5",
	}

	tests := []struct {
		name     string
		prefix   string
		expected []string
	}{
		{
			name:   "root memfs://",
			prefix: "memfs://",
			expected: []string{
				"memfs://",
				"/",
			},
		},
		{
			name:   "root memfs:///",
			prefix: "memfs:///",
			expected: []string{
				"memfs:///",
				"dir1/",
				"dir2/",
				"file1",
				"file2",
			},
		},
		{
			name:   "dir1",
			prefix: "memfs:///dir1/",
			expected: []string{
				"memfs:///dir1/",
				"file3",
				"file4",
			},
		},
		{
			name:   "partial dir",
			prefix: "memfs:///dir", // Should match dir1 and dir2, but logic is prefix based on full string?
			// Wait, runListDir uses TrimPrefix.
			// "memfs:///dir1/file3" trim "memfs:///dir" -> "1/file3"
			// first seg -> "1/" (because index of / is 1)
			// So completion offers "1/"
			expected: []string{
				"memfs:///dir",
				"1/",
				"2/",
			},
			// This is expected behavior for incremental completion.
		},
		{
			name:   "dir2",
			prefix: "memfs:///dir2/",
			expected: []string{
				"memfs:///dir2/",
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
