package jobs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestCreateJob(t *testing.T) {
	job := CreateJob("test job", "mod_test", "agent-1")
	if job == nil {
		t.Fatal("CreateJob returned nil")
	}
	if job.ID == "" {
		t.Error("Job ID is empty")
	}
	if job.Status != def.JobStatusPending {
		t.Errorf("Expected status Pending, got %v", job.Status)
	}

	retrieved := GetJob(job.ID)
	if retrieved == nil {
		t.Error("GetJob returned nil")
	}
	if retrieved.ID != job.ID {
		t.Errorf("Expected ID %s, got %s", job.ID, retrieved.ID)
	}
}

func TestHandleOutput(t *testing.T) {
	// Setup temporary workspace for testing
	tmpDir, err := os.MkdirTemp("", "emp3r0r_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Mock EmpWorkSpace
	originalWorkSpace := live.EmpWorkSpace
	live.EmpWorkSpace = tmpDir
	defer func() { live.EmpWorkSpace = originalWorkSpace }()

	job := CreateJob("output test", "mod_out", "agent-2")
	// ANSI colored output
	output := []byte("\x1b[31mtest output\x1b[0m")

	HandleOutput(job.ID, output)

	// Verify file content
	jobDir := filepath.Join(live.EmpWorkSpace, "jobs")
	logPath := filepath.Join(jobDir, fmt.Sprintf("%s.log", job.ID))
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	expected := "test output"
	if string(content) != expected {
		t.Errorf("Expected '%s', got '%s'", expected, string(content))
	}
}
