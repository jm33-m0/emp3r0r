package cc

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/donut"
)

// DonoutPE2Shellcode generates shellcode using donut for the executable files
func DonoutPE2Shellcode(executable_file, arch_choice string) {
	CliPrintInfo("Generating shellcode for: %s", executable_file)
	outfile := fmt.Sprintf("%s.bin", executable_file)
	out, err := DonutShellcodeFromFile(executable_file, outfile, arch_choice, false, "", "", "")
	if err != nil {
		CliPrintError("Donut: %s: %v", out, err)
		return
	}
	CliPrint("Generated shellcode:\n%s", out)
}

// DonutShellcodeFromFile returns a Donut shellcode for the given PE file
func DonutShellcodeFromFile(filePath string, outfile string, arch string, dotnet bool, params string, className string, method string) (out string, err error) {
	donutOps := donut.DonutOptions{
		InputPath:   filePath,
		OutputPath:  outfile,
		Arch:        donut.DonutArchMap[arch],
		BypassAMSI:  3,
		Compression: 2,
		Class:       className,
		Entropy:     3,
		Format:      1,
		Method:      method,
		Parameters:  params,
		Server:      "",
		RunThread:   true,
		UnicodeArgs: false,
		ExitOption:  1,
	}
	return donut.ExecuteDonut(filePath, donutOps)
}
