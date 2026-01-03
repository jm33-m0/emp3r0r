package cli

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestBuildTable(t *testing.T) {
	// Disable color for testing to make string comparison easier
	color.NoColor = true
	defer func() { color.NoColor = false }()

	header := []string{"Name", "Age", "Role"}
	rows := [][]string{
		{"Alice", "30", "Engineer"},
		{"Bob", "25", "Designer"},
	}

	result := BuildTable(header, rows)

	// Expected format based on BuildTable implementation:
	// [1] Name: Alice, Age: 30, Role: Engineer
	// [2] Name: Bob, Age: 25, Role: Designer
	//
	// Note: The implementation adds a newline at the end.

	expectedLines := []string{
		"[1] Name: Alice, Age: 30, Role: Engineer",
		"[2] Name: Bob, Age: 25, Role: Designer",
	}

	for _, line := range expectedLines {
		if !strings.Contains(result, line) {
			t.Errorf("BuildTable output missing expected line: %q\nGot:\n%s", line, result)
		}
	}

	// Test with empty rows
	resultEmpty := BuildTable(header, [][]string{})
	if strings.TrimSpace(resultEmpty) != "" {
		t.Errorf("BuildTable with empty rows should return empty string (or just newlines), got: %q", resultEmpty)
	}

	// Test with row longer than header
	rowsLong := [][]string{
		{"Alice", "30", "Engineer", "Extra"},
	}
	resultLong := BuildTable(header, rowsLong)
	if strings.Contains(resultLong, "Extra") {
		t.Errorf("BuildTable should ignore extra columns not in header")
	}
}
