package detection

import (
	"strings"
	"testing"
)

func TestReportFindingChangesSkipsVolatileFindings(t *testing.T) {
	cycles := []Cycle{
		{
			Iteration: 1, Execution: executionVerified,
			Summary: `{"execution":"verified","top_findings":["medium Elevated unbacked execute at Base: 0x1, Protection: 0x20, Size: 0x1","medium Callstack contains private memory regions","medium pe/checksum PE checksum"]}`,
		},
		{
			Iteration: 2, Execution: executionVerified,
			Summary: `{"execution":"verified","top_findings":[]}`,
		},
	}
	changes, _ := reportFindingChanges(cycles, 1, nil)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want only the stable pe/checksum finding", changes)
	}
	if !strings.Contains(changes[0].Finding, "pe/checksum") {
		t.Fatalf("change = %+v, want pe/checksum", changes[0])
	}
}
