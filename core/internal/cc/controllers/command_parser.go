package controllers

import (
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ParsedCommandOutput contains parsed command output
type ParsedCommandOutput struct {
	Headers []string
	Rows    [][]string
}

// ParsePSOutput parses process list CBOR data
func ParsePSOutput(data []byte) (*ParsedCommandOutput, error) {
	var procs []util.ProcEntry
	if err := cbor.Unmarshal(data, &procs); err != nil {
		return nil, fmt.Errorf("unmarshal ps: %w", err)
	}

	hasNamespace := false
	for _, p := range procs {
		if p.Namespace != "" && p.Namespace != "N/A" {
			hasNamespace = true
			break
		}
	}

	headers := []string{"PID", "PPID", "User", "UID"}
	if hasNamespace {
		headers = append(headers, "Namespace")
	}
	headers = append(headers, "Name", "Cmdline")

	result := &ParsedCommandOutput{
		Headers: headers,
		Rows:    [][]string{},
	}

	for _, p := range procs {
		pname := util.SplitLongLine(p.Name, 20)
		cmdline := util.SplitLongLine(p.Cmdline, 35)

		row := []string{
			strconv.Itoa(p.PID),
			strconv.Itoa(p.PPID),
			p.Token,
			p.UID,
		}
		if hasNamespace {
			row = append(row, p.Namespace)
		}
		row = append(row, pname, cmdline)
		result.Rows = append(result.Rows, row)
	}

	return result, nil
}

// ParseLSOutput parses directory listing CBOR data
func ParseLSOutput(data []byte) (*ParsedCommandOutput, error) {
	var dents []util.Dentry
	if err := cbor.Unmarshal(data, &dents); err != nil {
		return nil, fmt.Errorf("unmarshal ls: %w", err)
	}

	result := &ParsedCommandOutput{
		Headers: []string{"Name", "Type", "Size", "Time", "Permission"},
		Rows:    [][]string{},
	}

	for _, d := range dents {
		dname := util.SplitLongLine(d.Name, 20)
		result.Rows = append(result.Rows, []string{
			dname,
			d.Ftype,
			d.Size,
			d.Date,
			d.Permission,
		})
	}

	return result, nil
}

// ParseStatOutput parses file stat CBOR data
func ParseStatOutput(data []byte) (*ParsedCommandOutput, error) {
	var stat util.FileStat
	if err := cbor.Unmarshal(data, &stat); err != nil {
		return nil, fmt.Errorf("unmarshal stat: %w", err)
	}

	result := &ParsedCommandOutput{
		Headers: []string{"Name", "Size", "Perm", "Checksum"},
		Rows: [][]string{{
			stat.Name,
			fmt.Sprintf("%d", stat.Size),
			stat.Permission,
			stat.Checksum,
		}},
	}

	return result, nil
}
