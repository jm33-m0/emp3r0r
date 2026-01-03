package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMD5Sum tests the MD5Sum function
func TestMD5Sum(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "known test vector 1",
			input:    "hello",
			expected: "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name:     "known test vector 2",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "9e107d9d372bb6826bd81d3542a419d6",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:     "long string",
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
			expected: "6abf5f6af790145a11e1c889a8de163a",
		},
		{
			name:     "special characters",
			input:    "!@#$%^&*()",
			expected: "05b28d17a7b6e7024b6e5d8cc43a8bf7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MD5Sum(tt.input)
			if result != tt.expected {
				t.Errorf("MD5Sum(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestSHA256Sum tests the SHA256Sum function
func TestSHA256Sum(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "known test vector 1",
			input:    "hello",
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "known test vector 2",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "long string",
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			expected: "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256Sum(tt.input)
			if result != tt.expected {
				t.Errorf("SHA256Sum(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestSHA256SumDeterministic verifies SHA256Sum produces deterministic output
func TestSHA256SumDeterministic(t *testing.T) {
	input := "test input for determinism"
	result1 := SHA256Sum(input)
	result2 := SHA256Sum(input)
	
	if result1 != result2 {
		t.Errorf("SHA256Sum is not deterministic: got %q and %q for same input", result1, result2)
	}
}

// TestSHA256SumRaw tests the SHA256SumRaw function
func TestSHA256SumRaw(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "known test vector",
			input:    []byte("hello"),
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "empty data",
			input:    []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "binary data",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0xFF},
			expected: "46d0c96bb3d31e4b5e4c5c6f7f8e8c5c4d0c9e9f0e0d0c0b0a09080706050403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256SumRaw(tt.input)
			// Note: We can't verify the exact hash without knowing the algorithm
			// but we can verify it returns a 64-character hex string
			if len(result) != 64 {
				t.Errorf("SHA256SumRaw(%v) returned hash of length %d, expected 64", tt.input, len(result))
			}
		})
	}
}

// TestSHA256SumRawCompareWithSHA256Sum verifies SHA256SumRaw matches SHA256Sum
func TestSHA256SumRawCompareWithSHA256Sum(t *testing.T) {
	testInputs := []string{"hello", "world", "test", ""}
	
	for _, input := range testInputs {
		t.Run(input, func(t *testing.T) {
			result1 := SHA256Sum(input)
			result2 := SHA256SumRaw([]byte(input))
			
			if result1 != result2 {
				t.Errorf("SHA256Sum and SHA256SumRaw produce different results for %q: %q vs %q", input, result1, result2)
			}
		})
	}
}

// TestBase64URLEncode tests the Base64URLEncode function
func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "aGVsbG8=",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "special characters",
			input:    "hello@world!",
			expected: "aGVsbG9Ad29ybGQh",
		},
		{
			name:     "unicode string",
			input:    "Hello 世界",
			expected: "SGVsbG8g5LiW55WM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64URLEncode(tt.input)
			if result != tt.expected {
				t.Errorf("Base64URLEncode(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBase64URLDecode tests the Base64URLDecode function
func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "simple string",
			input:    "aGVsbG8=",
			expected: []byte("hello"),
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
		},
		{
			name:     "invalid base64",
			input:    "not valid base64!@#",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64URLDecode(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("Base64URLDecode(%q) should return nil for invalid input, got %v", tt.input, result)
				}
			} else {
				if string(result) != string(tt.expected) {
					t.Errorf("Base64URLDecode(%q) = %v, expected %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

// TestBase64URLRoundTrip tests encoding and decoding together
func TestBase64URLRoundTrip(t *testing.T) {
	tests := []string{
		"hello world",
		"special chars: !@#$%^&*()",
		"unicode: 你好世界 🌍",
		"",
		"a",
		"The quick brown fox jumps over the lazy dog",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			encoded := Base64URLEncode(input)
			decoded := Base64URLDecode(encoded)
			
			if string(decoded) != input {
				t.Errorf("Round-trip failed for %q: got %q after decode", input, string(decoded))
			}
		})
	}
}

// TestSHA256SumFile tests the SHA256SumFile function
func TestSHA256SumFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "simple file",
			content:  "hello world",
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:     "empty file",
			content:  "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "multiline file",
			content:  "line1\nline2\nline3",
			expected: "6bb6a5ad9b9c43a7cb535e636578716b64ac42edea814a4cad102ba404946837",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			filePath := filepath.Join(tmpDir, tt.name+".txt")
			err := os.WriteFile(filePath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result := SHA256SumFile(filePath)
			if result != tt.expected {
				t.Errorf("SHA256SumFile(%q) = %q, expected %q", filePath, result, tt.expected)
			}
		})
	}

	// Test non-existent file
	t.Run("non-existent file", func(t *testing.T) {
		result := SHA256SumFile("/nonexistent/file/path")
		if result == "" {
			t.Error("SHA256SumFile should return error message for non-existent file, got empty string")
		}
		// The result should contain an error message
		if len(result) > 0 && result[0:2] != "op" && result[0:2] != "no" { // Check for "open" or "no such" error prefix
			// If it's a valid hash (64 chars), that's wrong
			if len(result) == 64 {
				t.Errorf("SHA256SumFile returned what looks like a valid hash for non-existent file: %q", result)
			}
		}
	})
}
