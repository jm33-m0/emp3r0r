package util

import (
	"os"
	"path/filepath"
	"testing"
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
