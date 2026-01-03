package util

import (
	"os"
	"testing"
)

func TestIsTextFile(t *testing.T) {
	// Create a temporary text file
	tmpText, err := os.CreateTemp("", "test_text_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpText.Name())

	textContent := "This is a text file.\nIt contains printable characters."
	if _, err := tmpText.WriteString(textContent); err != nil {
		t.Fatal(err)
	}
	tmpText.Close()

	isText, err := isTextFile(tmpText.Name())
	if err != nil {
		t.Errorf("isTextFile failed: %v", err)
	}
	if !isText {
		t.Errorf("Expected text file to be identified as text")
	}

	// Create a temporary binary file
	tmpBin, err := os.CreateTemp("", "test_bin_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpBin.Name())

	// Write some null bytes and non-printable characters
	binContent := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	if _, err := tmpBin.Write(binContent); err != nil {
		t.Fatal(err)
	}
	tmpBin.Close()

	isText, err = isTextFile(tmpBin.Name())
	if err != nil {
		t.Errorf("isTextFile failed: %v", err)
	}
	if isText {
		t.Errorf("Expected binary file to be identified as binary")
	}
}
