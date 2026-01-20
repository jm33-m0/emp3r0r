package util

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/arc/v2"
)

func TestSaveFileAgent(t *testing.T) {
	tmpDir := t.TempDir()

	// Test StorageMemory
	memFile := filepath.Join(tmpDir, "mem_test.txt")
	data := []byte("memory file content")
	err := SaveFileAgent(memFile, data, 0600, StorageMemory)
	if err != nil {
		t.Fatalf("Failed to save to memory: %v", err)
	}

	if !IsFileExist(memFile) {
		t.Error("IsFileExist returned false for memory file")
	}

	readData, err := ReadFileAgent(memFile)
	if err != nil {
		t.Fatalf("Failed to read memory file: %v", err)
	}
	if string(readData) != string(data) {
		t.Errorf("Content mismatch. Got %s, want %s", string(readData), string(data))
	}

	// Check it is NOT on disk
	_, err = os.Stat(memFile)
	if !os.IsNotExist(err) {
		t.Error("File found on disk, expected memory only")
	}

	// Test StorageDisk
	diskFile := filepath.Join(tmpDir, "disk_test.txt")
	diskData := []byte("disk file content")
	err = SaveFileAgent(diskFile, diskData, 0600, StorageDisk)
	if err != nil {
		t.Fatalf("Failed to save to disk: %v", err)
	}

	if !IsFileExist(diskFile) {
		t.Error("IsFileExist returned false for disk file")
	}

	// Check it IS on disk
	_, err = os.Stat(diskFile)
	if os.IsNotExist(err) {
		t.Error("File not found on disk, expected disk storage")
	}

	// Test StorageAuto (Small file -> Memory)
	autoFile := filepath.Join(tmpDir, "auto_test.txt")
	autoData := []byte("auto file content")
	err = SaveFileAgent(autoFile, autoData, 0600, StorageAuto)
	if err != nil {
		t.Fatalf("Failed to save auto: %v", err)
	}

	// Should be in memory (assuming system has memory)
	MemFileLock.RLock()
	_, inMem := MemFileMap[autoFile]
	MemFileLock.RUnlock()

	if !inMem {
		t.Log("Auto strategy chose Disk (might be low memory environment or logic change)")
	} else {
		// Verify not on disk
		_, err = os.Stat(autoFile)
		if !os.IsNotExist(err) {
			t.Error("Auto file found on disk, expected memory for small file")
		}
	}

	// Test Checksum logic (simulating what putCmdRun does)
	readAutoData, err := ReadFileAgent(autoFile)
	if err != nil {
		t.Fatalf("Failed to read auto file: %v", err)
	}
	if string(readAutoData) != string(autoData) {
		t.Errorf("Auto file content mismatch")
	}
}

func TestUnarchiveAgent_ZipSlip(t *testing.T) {
	tmpDir := t.TempDir()
	dstDir := filepath.Join(tmpDir, "extract")
	err := os.MkdirAll(dstDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create dst dir: %v", err)
	}

	// Create a malicious tarball content
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var files = []struct {
		Name, Body string
	}{
		{"safe.txt", "safe content"},
		{"../evil.txt", "evil content"},
		{"/tmp/evil2.txt", "evil content"},
	}
	for _, file := range files {
		hdr := &tar.Header{
			Name: file.Name,
			Mode: 0600,
			Size: int64(len(file.Body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(file.Body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// Compress it to XZ
	tarData := buf.Bytes()
	xzData, err := arc.CompressXz(tarData)
	if err != nil {
		t.Fatalf("Failed to compress tarball: %v", err)
	}

	// Save it using SaveFileAgent (so ReadFileAgent can read it)
	tarballPath := filepath.Join(tmpDir, "malicious.tar.xz")
	err = SaveFileAgent(tarballPath, xzData, 0600, StorageMemory)
	if err != nil {
		t.Fatalf("Failed to save tarball: %v", err)
	}

	// Attempt to unarchive
	err = UnarchiveAgent(tarballPath, dstDir)
	if err == nil {
		t.Error("UnarchiveAgent should have failed due to Zip Slip")
	} else if !strings.Contains(err.Error(), "unsafe tar header name") {
		t.Errorf("Expected Zip Slip error, got: %v", err)
	}

	// Verify evil.txt was NOT created outside dstDir
	evilPath := filepath.Join(tmpDir, "evil.txt")
	if _, err := os.Stat(evilPath); err == nil {
		t.Errorf("Zip Slip successful! %s was created", evilPath)
	}
}
