package util

import (
	"os"
	"testing"
)

func TestMemFileOperations(t *testing.T) {
	// 1. WriteFileAgent with mem:// prefix
	filepath := "mem:///test_file.txt"
	content := []byte("hello world")
	err := WriteFileAgent(filepath, content, 0600)
	if err != nil {
		t.Fatalf("WriteFileAgent failed: %v", err)
	}

	// Verify it exists in memory map
	if !IsFileExist(filepath) {
		t.Errorf("IsFileExist returned false for %s", filepath)
	}

	MemFileLock.RLock()
	_, ok := MemFileMap[filepath]
	MemFileLock.RUnlock()
	if !ok {
		t.Errorf("File not found in MemFileMap: %s", filepath)
	}

	// 2. ReadFileAgent
	readData, err := ReadFileAgent(filepath)
	if err != nil {
		t.Fatalf("ReadFileAgent failed: %v", err)
	}
	if string(readData) != string(content) {
		t.Errorf("ReadFileAgent content mismatch: got %s, want %s", readData, content)
	}

	// 3. CopyAgent mem:// to mem://
	dstPath := "mem:///copy_test.txt"
	err = CopyAgent(filepath, dstPath)
	if err != nil {
		t.Fatalf("CopyAgent mem->mem failed: %v", err)
	}

	if !IsFileExist(dstPath) {
		t.Errorf("Copy destination %s does not exist", dstPath)
	}

	readCopy, err := ReadFileAgent(dstPath)
	if err != nil {
		t.Fatalf("ReadFileAgent copy failed: %v", err)
	}
	if string(readCopy) != string(content) {
		t.Errorf("Copy content mismatch")
	}

	// 4. CopyAgent mem:// to disk
	diskPath := "/tmp/disk_copy_test.txt"
	defer os.Remove(diskPath)
	err = CopyAgent(filepath, diskPath)
	if err != nil {
		t.Fatalf("CopyAgent mem->disk failed: %v", err)
	}

	if !IsFileExist(diskPath) {
		t.Errorf("Disk copy %s does not exist", diskPath)
	}

	// Read back from disk (will decrypt)
	// Note: WriteFileAgent encrypts. ReadFileAgent decrypts.
	// We are testing unified flow so it should match.
	readDisk, err := ReadFileAgent(diskPath)
	if err != nil {
		t.Fatalf("ReadFileAgent disk failed: %v", err)
	}
	if string(readDisk) != string(content) {
		t.Errorf("Disk copy content mismatch")
	}

	// 5. Cleanup
	RemoveFileAgent(filepath)
	RemoveFileAgent(dstPath)

	if IsFileExist(filepath) {
		t.Errorf("RemoveFileAgent failed to remove %s", filepath)
	}
}

func TestListMemFiles(t *testing.T) {
	MemFileLock.Lock()
	// clean map
	for k := range MemFileMap {
		delete(MemFileMap, k)
	}
	MemFileMap["mem:///file1"] = []byte("1")
	MemFileMap["mem:///file2"] = []byte("2")
	MemFileMap["/tmp/not_mem"] = []byte("3")
	MemFileLock.Unlock()

	files := ListMemFiles()
	if len(files) != 2 {
		t.Errorf("ListMemFiles returned %d files, want 2. Got: %v", len(files), files)
	}

	found1 := false
	found2 := false
	for _, f := range files {
		if f == "mem:///file1" {
			found1 = true
		}
		if f == "mem:///file2" {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("ListMemFiles missing expected files. Got: %v", files)
	}
}
