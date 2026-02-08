package controllers

import (
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ParsedCommandOutput contains parsed command output
type ParsedCommandOutput struct {
	Headers []string
	Rows    [][]string
}

// ParseSysinfoOutput parses sysinfo CBOR data into table format
func ParseSysinfoOutput(data []byte) (*ParsedCommandOutput, error) {
	var info def.Emp3r0rAgent
	if err := cbor.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("unmarshal sysinfo: %w", err)
	}

	result := &ParsedCommandOutput{
		Headers: []string{},
		Rows:    [][]string{},
	}

	var row []string

	addIfNotEmpty := func(name, value string) {
		if value != "" && value != "[]" && value != "0" {
			result.Headers = append(result.Headers, name)
			row = append(row, value)
		}
	}

	addIfNotEmpty("Hostname", info.Hostname)
	addIfNotEmpty("Uptime", info.Uptime)
	addIfNotEmpty("OS", info.OS)
	addIfNotEmpty("Kernel", info.Kernel)
	addIfNotEmpty("Arch", info.Arch)
	addIfNotEmpty("CPU", info.CPU)
	addIfNotEmpty("Mem", info.Mem)
	addIfNotEmpty("User", info.User)
	addIfNotEmpty("Groups", info.Groups)
	addIfNotEmpty("IPs", fmt.Sprintf("%v", info.IPs))
	if info.Container != "" && info.Container != "N/A" {
		addIfNotEmpty("Container", info.Container)
	}
	if info.Process != nil {
		addIfNotEmpty("Agent PID", strconv.Itoa(info.Process.PID))
	}
	addIfNotEmpty("CWD", info.CWD)
	addIfNotEmpty("Transport", info.Transport)

	result.Rows = [][]string{row}
	return result, nil
}

// ParsePSOutput parses process list CBOR data
func ParsePSOutput(data []byte) (*ParsedCommandOutput, error) {
	var procs []util.ProcEntry
	if err := cbor.Unmarshal(data, &procs); err != nil {
		return nil, fmt.Errorf("unmarshal ps: %w", err)
	}

	result := &ParsedCommandOutput{
		Headers: []string{"Name", "PID", "PPID", "User"},
		Rows:    [][]string{},
	}

	for _, p := range procs {
		pname := util.SplitLongLine(p.Name, 20)
		result.Rows = append(result.Rows, []string{
			pname,
			strconv.Itoa(p.PID),
			strconv.Itoa(p.PPID),
			p.Token,
		})
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
