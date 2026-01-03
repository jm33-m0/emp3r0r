package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TempDir creates a temporary directory for tests and registers cleanup
// Deprecated: Use t.TempDir() instead, which is built into Go's testing package
func TempDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// CreateTempFile creates a temporary file with the given content and returns the path
func CreateTempFile(t *testing.T, dir, filename, content string) string {
	t.Helper()

	filePath := filepath.Join(dir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file %s: %v", filePath, err)
	}

	return filePath
}

// AssertEqual checks if two values are equal
func AssertEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// AssertError checks that an error occurred
func AssertError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected error but got nil", msg)
	}
}

// AssertNoError checks that no error occurred
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// AssertTrue checks that a condition is true
func AssertTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Errorf("assertion failed: %s", msg)
	}
}

// AssertFalse checks that a condition is false
func AssertFalse(t *testing.T, condition bool, msg string) {
	t.Helper()
	if condition {
		t.Errorf("assertion failed: %s", msg)
	}
}

// AssertNil checks that a value is nil
func AssertNil(t *testing.T, value interface{}) {
	t.Helper()
	if value != nil {
		// For better nil checking with interfaces, use reflection
		// A typed nil pointer (e.g., var x *int = nil) will not equal nil when boxed in interface{}
		// But for simplicity in tests, we'll just check direct nil
		t.Errorf("expected nil but got %v (type: %T)", value, value)
	}
}

// AssertNotNil checks that a value is not nil
func AssertNotNil(t *testing.T, value interface{}) {
	t.Helper()
	if value == nil {
		t.Error("expected non-nil value but got nil")
	}
}

// AssertStringContains checks that a string contains a substring
func AssertStringContains(t *testing.T, str, substr string) {
	t.Helper()
	if !contains(str, substr) {
		t.Errorf("expected %q to contain %q", str, substr)
	}
}

// contains is a simple helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
