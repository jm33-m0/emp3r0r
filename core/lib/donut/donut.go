package donut

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// DonoutPE2Shellcode generates shellcode using donut for the executable files
func DonoutPE2Shellcode(executable_file, arch_choice string) {
	logging.Infof("Generating shellcode for: %s", executable_file)
	outfile := fmt.Sprintf("%s.bin", executable_file)
	out, err := DonutShellcodeFromFile(executable_file, outfile, arch_choice, false, "", "", "")
	if err != nil {
		logging.Errorf("Donut: %s: %v", out, err)
		return
	}
	logging.Infof("Generated shellcode:\n%s", out)
}

// DonutShellcodeFromFile returns a Donut shellcode for the given PE file
func DonutShellcodeFromFile(filePath, outfile, arch string, dotnet bool, params, className, method string) (out string, err error) {
	donutOps := DonutOptions{
		InputPath:   filePath,
		OutputPath:  outfile,
		Arch:        DonutArchMap[arch],
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
	return ExecuteDonut(filePath, donutOps)
}
