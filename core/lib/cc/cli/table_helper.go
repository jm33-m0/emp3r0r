package cli

import (
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

// BuildTable creates and renders a table with the given header and rows.
func BuildTable(header []string, rows [][]string) string {
	builder := &strings.Builder{}
	table := tablewriter.NewWriter(builder)
	table.SetHeader(header)

	// Dynamic header colors based on arbitrary header length.
	defaultHeaderColors := []tablewriter.Colors{
		{tablewriter.Bold, tablewriter.FgHiMagentaColor},
		{tablewriter.Bold, tablewriter.FgBlueColor},
		{tablewriter.Bold, tablewriter.FgHiWhiteColor},
		{tablewriter.Bold, tablewriter.FgHiCyanColor},
		{tablewriter.Bold, tablewriter.FgHiYellowColor},
	}
	headerColors := make([]tablewriter.Colors, len(header))
	for i := range header {
		headerColors[i] = defaultHeaderColors[i%len(defaultHeaderColors)]
	}
	table.SetHeaderColor(headerColors...)

	// Dynamic column colors based on arbitrary header length.
	defaultColumnColors := []tablewriter.Colors{
		{tablewriter.FgHiMagentaColor},
		{tablewriter.FgBlueColor},
		{tablewriter.FgHiWhiteColor},
		{tablewriter.FgHiCyanColor},
		{tablewriter.FgYellowColor},
	}
	columnColors := make([]tablewriter.Colors, len(header))
	for i := range header {
		columnColors[i] = defaultColumnColors[i%len(defaultColumnColors)]
	}
	table.SetColumnColor(columnColors...)

	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	table.SetReflowDuringAutoWrap(true)
	table.SetColWidth(20)
	table.AppendBulk(rows)
	table.Render()
	return builder.String()
}

// automatically resize CommandPane according to table width
func AdaptiveTable(tableString string) {
	TmuxUpdatePanes()
	row_len := len(strings.Split(tableString, "\n")[0])
	if OutputPane.Width < row_len {
		logging.Debugf("Command Pane %d vs %d table width, resizing", CommandPane.Width, row_len)
		OutputPane.ResizePane("x", row_len)
	}
}

// CliPrettyPrint prints two-column help info
func CliPrettyPrint(header1, header2 string, map2write *map[string]string) {
	// build table rows using existing helper to split long lines
	rows := [][]string{}
	for c1, c2 := range *map2write {
		rows = append(rows, []string{
			util.SplitLongLine(c1, 50),
			util.SplitLongLine(c2, 50),
		})
	}
	// reuse BuildTable helper
	tableStr := BuildTable([]string{header1, header2}, rows)

	AdaptiveTable(tableStr)
	logging.Printf("\n%s", tableStr)
}
