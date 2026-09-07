package shellhelper

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// cmdPS_test.go — real unit coverage for the agent's process-listing CBOR
// response (replaces the old empty dummy test).

func TestCmdPS_ReturnsWellFormedCBOR(t *testing.T) {
	out, err := CmdPS(0, "", "", "")
	if err != nil {
		t.Fatalf("CmdPS: %v", err)
	}
	var procs []util.ProcEntry
	if err := cbor.Unmarshal(out, &procs); err != nil {
		t.Fatalf("CmdPS output is not valid CBOR: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("CmdPS returned no process entries")
	}
	// Every entry must be well-formed enough to render in the operator table.
	for _, p := range procs {
		if p.PID < 0 {
			t.Fatalf("negative pid %d in entry %+v", p.PID, p)
		}
	}
}

func TestCmdPS_FilterByPID(t *testing.T) {
	// Current test process must exist; asking for an impossible PID yields the
	// N/A sentinel entry rather than an empty failure.
	out, err := CmdPS(1<<30, "", "", "") // 2^30 — practically never a real PID
	if err != nil {
		t.Fatalf("CmdPS: %v", err)
	}
	var procs []util.ProcEntry
	if err := cbor.Unmarshal(out, &procs); err != nil {
		t.Fatalf("CmdPS output is not valid CBOR: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("CmdPS(impossible pid) returned empty list")
	}
	// The sentinel entry has PID 0 and "N/A" name.
	if procs[0].PID != 0 || !strings.Contains(procs[0].Name, "N/A") {
		t.Fatalf("expected N/A sentinel, got %+v", procs[0])
	}
}
