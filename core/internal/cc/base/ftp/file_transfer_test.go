package ftp

import (
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestStatFile(t *testing.T) {
	// Mock ExecCmd
	ExecCmd = func(cmd, cmd_id, tag string) error {
		// Simulate agent response
		go func() {
			time.Sleep(100 * time.Millisecond)
			fstat := &util.FileStat{
				Name:       "testfile",
				Size:       1234,
				Checksum:   "sha256sum",
				Permission: "-rw-r--r--",
			}
			data, err := cbor.Marshal(fstat)
			if err != nil {
				t.Errorf("Failed to marshal fstat: %v", err)
				return
			}
			live.CmdResults.Store(cmd_id, string(data))
		}()
		return nil
	}

	// Initialize live.CmdResults
	live.CmdResults = sync.Map{}

	agent := &def.Emp3r0rAgent{
		Tag: "test-agent",
	}

	fi, err := StatFile("testfile", agent)
	if err != nil {
		t.Fatalf("StatFile failed: %v", err)
	}

	if fi.Name != "testfile" {
		t.Errorf("Name mismatch: got %s, want testfile", fi.Name)
	}
	if fi.Size != 1234 {
		t.Errorf("Size mismatch: got %d, want 1234", fi.Size)
	}
}
