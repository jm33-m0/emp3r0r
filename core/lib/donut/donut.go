package donut

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// Create a map to map Go architecture (GOARCH) to Donut architecture values
var DonutArchMap = map[string]int{
	"386":   1, // x86 (32-bit)
	"amd64": 2, // amd64 (64-bit)
	"arm64": 2, // arm64 maps to amd64 for Donut
}

// DonutOptions holds the configuration options for the Donut binary.
type DonutOptions struct {
	InputPath   string // Path to input file
	Arch        int    // Target architecture (1=x86, 2=amd64, 3=x86+amd64)
	BypassAMSI  int    // Behavior for bypassing AMSI/WLDP (1=None, 2=Abort, 3=Continue)
	PreservePE  int    // Preserve PE headers (1=Overwrite, 2=Keep all)
	Decoy       string // Path to decoy module for Module Overloading
	Class       string // Class name (required for .NET DLL)
	AppDomain   string // AppDomain name for .NET
	Entropy     int    // Entropy level (1=None, 2=Random names, 3=Random + encryption)
	Format      int    // Output format (1=Binary, 2=Base64, etc.)
	Method      string // Method or function for DLL
	ModuleName  string // Module name for HTTP staging
	OutputPath  string // Path to save the loader
	Parameters  string // Command-line parameters for EXE/DLL
	Runtime     string // CLR runtime version
	Server      string // URL for HTTP server hosting Donut module
	RunThread   bool   // Run entry point as a thread
	UnicodeArgs bool   // Pass command line as Unicode
	ExitOption  int    // Loader exit behavior (1=exit thread, 2=exit process, etc.)
	OffsetAddr  string // Offset address for loader continuation
	Compression int    // Pack/compress input file (1=None, 2=aPLib, etc.)
}

// GenerateCommand builds the Donut command based on the options.
func (opts *DonutOptions) GenerateCommand(input string) ([]string, error) {
	if input == "" {
		return nil, errors.New("input file is required")
	}

	cmd := []string{input}

	if opts.InputPath != "" {
		cmd = append(cmd, "-i", opts.InputPath)
	}
	if opts.Arch != 0 {
		cmd = append(cmd, "-a", strconv.Itoa(opts.Arch))
	}
	if opts.BypassAMSI != 0 {
		cmd = append(cmd, "-b", strconv.Itoa(opts.BypassAMSI))
	}
	if opts.PreservePE != 0 {
		cmd = append(cmd, "-k", strconv.Itoa(opts.PreservePE))
	}
	if opts.Decoy != "" {
		cmd = append(cmd, "-j", opts.Decoy)
	}
	if opts.Class != "" {
		cmd = append(cmd, "-c", opts.Class)
	}
	if opts.AppDomain != "" {
		cmd = append(cmd, "-d", opts.AppDomain)
	}
	if opts.Entropy != 0 {
		cmd = append(cmd, "-e", strconv.Itoa(opts.Entropy))
	}
	if opts.Format != 0 {
		cmd = append(cmd, "-f", strconv.Itoa(opts.Format))
	}
	if opts.Method != "" {
		cmd = append(cmd, "-m", opts.Method)
	}
	if opts.ModuleName != "" {
		cmd = append(cmd, "-n", opts.ModuleName)
	}
	if opts.OutputPath != "" {
		cmd = append(cmd, "-o", opts.OutputPath)
	}
	if opts.Parameters != "" {
		cmd = append(cmd, "-p", opts.Parameters)
	}
	if opts.Runtime != "" {
		cmd = append(cmd, "-r", opts.Runtime)
	}
	if opts.Server != "" {
		cmd = append(cmd, "-s", opts.Server)
	}
	if opts.RunThread {
		cmd = append(cmd, "-t")
	}
	if opts.UnicodeArgs {
		cmd = append(cmd, "-w")
	}
	if opts.ExitOption != 0 {
		cmd = append(cmd, "-x", strconv.Itoa(opts.ExitOption))
	}
	if opts.OffsetAddr != "" {
		cmd = append(cmd, "-y", opts.OffsetAddr)
	}
	if opts.Compression != 0 {
		cmd = append(cmd, "-z", strconv.Itoa(opts.Compression))
	}

	return cmd, nil
}

// ExecuteDonut runs the Donut binary with the provided options.
func ExecuteDonut(input string, opts DonutOptions) (string, error) {
	// check if donut is available
	_, err := exec.LookPath("donut")
	if err != nil {
		return "", errors.New("donut binary not found in PATH, download it from https://github.com/TheWover/donut/releases and put it in your PATH")
	}

	cmdArgs, err := opts.GenerateCommand(input)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("donut", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.New(string(output))
	}

	return strings.TrimSpace(string(output)), nil
}
