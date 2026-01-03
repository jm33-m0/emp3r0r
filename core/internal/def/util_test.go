package def

import (
	"testing"
)

func TestGenAESKey(t *testing.T) {
	seed := "test_seed"
	key := GenAESKey(seed)

	if len(key) != 32 {
		t.Errorf("GenAESKey returned key of length %d, expected 32", len(key))
	}

	// Ensure determinism
	key2 := GenAESKey(seed)
	if string(key) != string(key2) {
		t.Errorf("GenAESKey is not deterministic")
	}

	// Ensure different seeds produce different keys
	key3 := GenAESKey("different_seed")
	if string(key) == string(key3) {
		t.Errorf("GenAESKey produced same key for different seeds")
	}
}

func TestMd5Sum(t *testing.T) {
	text := "hello world"
	expected := "5eb63bbbe01eeed093cb22bb8f5acdc3"
	result := md5Sum(text)

	if result != expected {
		t.Errorf("md5Sum(%q) = %q, expected %q", text, result, expected)
	}
}
