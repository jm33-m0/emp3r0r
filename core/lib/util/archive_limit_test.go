package util

import (
	"bytes"
	"testing"
)

func TestDecompressLimitBoundsOutput(t *testing.T) {
	compressed, err := Compress(bytes.Repeat([]byte{0}, 4096))
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	if _, err := DecompressLimit(compressed, 1024); err == nil {
		t.Fatal("DecompressLimit accepted output larger than its limit")
	}
	out, err := DecompressLimit(compressed, 4096)
	if err != nil {
		t.Fatalf("DecompressLimit: %v", err)
	}
	if len(out) != 4096 {
		t.Fatalf("decompressed %d bytes, want 4096", len(out))
	}
}
