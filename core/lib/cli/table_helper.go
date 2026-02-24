package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// BuildTable creates a simple formatted list instead of a complex table
func BuildTable(header []string, rows [][]string) string {
	var result strings.Builder

	// Print rows as simple formatted list
	for i, row := range rows {
		result.WriteString(color.HiBlueString("[%d] ", i+1))

		// Format each row as "Column1: Value1, Column2: Value2, ..."
		var parts []string
		for j, cell := range row {
			if j < len(header) {
				parts = append(parts, fmt.Sprintf("%s: %s",
					color.HiCyanString(header[j]),
					color.WhiteString(cell)))
			}
		}
		result.WriteString(strings.Join(parts, ", "))
		result.WriteString("\n")
	}

	result.WriteString("\n")
	return result.String()
}

// AdaptiveTable is now a no-op since we don't need to resize for simple text
func AdaptiveTable(tableString string) {
	// Nothing to do - simple text formatting doesn't need pane resizing
	logging.Debugf("Using simple text formatting - no pane resizing needed")
}

// CliPrettyPrint prints two-column help info using simple formatting
func CliPrettyPrint(header1, header2 string, map2write *map[string]string) {
	for c1, c2 := range *map2write {
		// Split long lines to fit better
		c1_split := util.SplitLongLine(c1, 40)
		c2_split := util.SplitLongLine(c2, 60)

		logging.Infof("%s: %s\n",
			color.HiCyanString("%-40s", c1_split),
			color.WhiteString(c2_split))
	}
	logging.Infof("\n")
}
