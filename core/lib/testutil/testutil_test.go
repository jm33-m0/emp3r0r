package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTempDir tests the TempDir function
func TestTempDir(t *testing.T) {
	dir := TempDir(t)
	
	// Verify directory was created
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("TempDir() did not create directory: %v", err)
	}
}

// TestCreateTempFile tests the CreateTempFile function
func TestCreateTempFile(t *testing.T) {
	dir := t.TempDir()
	content := "test content"
	filename := "test.txt"
	
	path := CreateTempFile(t, dir, filename, content)
	
	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("CreateTempFile() did not create file: %v", err)
	}
	
	// Verify content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	
	if string(data) != content {
		t.Errorf("CreateTempFile() content = %q, want %q", string(data), content)
	}
	
	// Verify path is correct
	expectedPath := filepath.Join(dir, filename)
	if path != expectedPath {
		t.Errorf("CreateTempFile() path = %q, want %q", path, expectedPath)
	}
}

// TestAssertEqual tests the AssertEqual function
func TestAssertEqual(t *testing.T) {
	// This is a meta-test - we're testing our test helpers
	// We can't easily test failure cases without creating a mock testing.T
	
	// Test success case
	AssertEqual(t, 1, 1)
	AssertEqual(t, "hello", "hello")
}

// TestAssertError tests the AssertError function
func TestAssertError(t *testing.T) {
	err := os.ErrNotExist
	AssertError(t, err, "test error")
}

// TestAssertNoError tests the AssertNoError function
func TestAssertNoError(t *testing.T) {
	AssertNoError(t, nil)
}

// TestAssertTrue tests the AssertTrue function
func TestAssertTrue(t *testing.T) {
	AssertTrue(t, true, "should be true")
}

// TestAssertFalse tests the AssertFalse function
func TestAssertFalse(t *testing.T) {
	AssertFalse(t, false, "should be false")
	AssertFalse(t, 1 == 2, "1 should not equal 2")
}

// TestAssertNil tests the AssertNil function
func TestAssertNil(t *testing.T) {
	// Note: In Go, a typed nil pointer (var ptr *int = nil) is not equal to nil
	// when passed as interface{}. For test purposes, we test with untyped nil.
	AssertNil(t, nil)
}

// TestAssertNotNil tests the AssertNotNil function
func TestAssertNotNil(t *testing.T) {
	value := 42
	ptr := &value
	AssertNotNil(t, ptr)
}

// TestAssertStringContains tests the AssertStringContains function
func TestAssertStringContains(t *testing.T) {
	AssertStringContains(t, "hello world", "hello")
	AssertStringContains(t, "hello world", "world")
	AssertStringContains(t, "hello world", "o w")
	AssertStringContains(t, "hello world", "")
}

// TestContains tests the contains helper function
func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		str      string
		substr   string
		expected bool
	}{
		{
			name:     "contains at start",
			str:      "hello world",
			substr:   "hello",
			expected: true,
		},
		{
			name:     "contains at end",
			str:      "hello world",
			substr:   "world",
			expected: true,
		},
		{
			name:     "contains in middle",
			str:      "hello world",
			substr:   "o w",
			expected: true,
		},
		{
			name:     "does not contain",
			str:      "hello world",
			substr:   "xyz",
			expected: false,
		},
		{
			name:     "empty substring",
			str:      "hello",
			substr:   "",
			expected: true,
		},
		{
			name:     "empty string",
			str:      "",
			substr:   "hello",
			expected: false,
		},
		{
			name:     "both empty",
			str:      "",
			substr:   "",
			expected: true,
		},
		{
			name:     "exact match",
			str:      "hello",
			substr:   "hello",
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.str, tt.substr)
			if result != tt.expected {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.str, tt.substr, result, tt.expected)
			}
		})
	}
}
