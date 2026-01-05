//go:build linux
// +build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestCCInit(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "emp3r0r_cc_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create necessary directory structure
	// emp3r0r expects Prefix + "/lib/emp3r0r"
	empLibDir := filepath.Join(tempDir, "lib", "emp3r0r")
	err = os.MkdirAll(empLibDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create emp3r0r lib dir: %v", err)
	}

	// Create dummy emp3r0r-cat
	catPath := filepath.Join(empLibDir, "emp3r0r-cat")
	err = os.WriteFile(catPath, []byte("dummy"), 0755)
	if err != nil {
		t.Fatalf("Failed to create dummy emp3r0r-cat: %v", err)
	}

	// Set EMP3R0R_PREFIX environment variable
	os.Setenv("EMP3R0R_PREFIX", tempDir)
	defer os.Unsetenv("EMP3R0R_PREFIX")

	// Test SetupFilePaths
	err = live.SetupFilePaths()
	if err != nil {
		t.Fatalf("SetupFilePaths failed: %v", err)
	}

	// Verify EmpDataDir
	if live.EmpDataDir != empLibDir {
		t.Errorf("Expected EmpDataDir to be %s, got %s", empLibDir, live.EmpDataDir)
	}

	// Test setupLogging
	// setupLogging uses live.EmpLogFile which is set by SetupFilePaths
	setupLogging()

	// Verify log file creation
	if _, err := os.Stat(live.EmpLogFile); os.IsNotExist(err) {
		t.Errorf("Log file was not created at %s", live.EmpLogFile)
	}
}
