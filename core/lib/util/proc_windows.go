//go:build windows
// +build windows

package util

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"golang.org/x/sys/windows"
)

var (
	modntdll                      = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
	procNtQuerySystemInformation  = modntdll.NewProc("NtQuerySystemInformation")
)

type processBasicInformation struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type systemProcessItem struct {
	PID  int
	PPID int
	Name string
}

func getSystemProcessInformation() ([]systemProcessItem, error) {
	var bufSize uint32 = 0x20000 // 128 KB initial buffer
	buf := make([]byte, bufSize)
	var returnLen uint32

	for {
		status, _, _ := procNtQuerySystemInformation.Call(
			5, // SystemProcessInformation
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if status == 0 { // STATUS_SUCCESS
			break
		}
		if status == 0xc0000004 { // STATUS_INFO_LENGTH_MISMATCH
			if returnLen > uint32(len(buf)) {
				bufSize = returnLen + 0x4000
			} else {
				bufSize *= 2
			}
			buf = make([]byte, bufSize)
		} else {
			return nil, fmt.Errorf("NtQuerySystemInformation status 0x%x", status)
		}
	}

	var items []systemProcessItem
	offset := 0
	is64Bit := unsafe.Sizeof(uintptr(0)) == 8

	for offset < len(buf) {
		if offset+96 > len(buf) {
			break
		}

		nextOffset := int(*(*uint32)(unsafe.Pointer(&buf[offset])))

		var imgLen uint16
		var imgBuf uintptr
		var pidVal uintptr
		var ppidVal uintptr

		if is64Bit {
			imgLen = *(*uint16)(unsafe.Pointer(&buf[offset+56]))
			imgBuf = *(*uintptr)(unsafe.Pointer(&buf[offset+64]))
			pidVal = *(*uintptr)(unsafe.Pointer(&buf[offset+80]))
			ppidVal = *(*uintptr)(unsafe.Pointer(&buf[offset+88]))
		} else {
			imgLen = *(*uint16)(unsafe.Pointer(&buf[offset+56]))
			imgBuf = *(*uintptr)(unsafe.Pointer(&buf[offset+60]))
			pidVal = *(*uintptr)(unsafe.Pointer(&buf[offset+68]))
			ppidVal = *(*uintptr)(unsafe.Pointer(&buf[offset+72]))
		}

		pid := int(pidVal)
		ppid := int(ppidVal)

		var name string
		if imgBuf != 0 && imgLen > 0 {
			bufStart := uintptr(unsafe.Pointer(&buf[0]))
			bufEnd := bufStart + uintptr(len(buf))
			if imgBuf >= bufStart && imgBuf+uintptr(imgLen) <= bufEnd {
				strOffset := imgBuf - bufStart
				utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[strOffset])), imgLen/2)
				name = windows.UTF16ToString(utf16Slice)
			} else {
				name = "unknown_proc"
			}
		} else if pid == 0 {
			name = "System Idle Process"
		} else if pid == 4 {
			name = "System"
		} else {
			name = "unknown_proc"
		}

		items = append(items, systemProcessItem{
			PID:  pid,
			PPID: ppid,
			Name: name,
		})

		if nextOffset == 0 {
			break
		}
		offset += nextOffset
	}

	return items, nil
}

// ProcessList a list of current processes with filters on Windows
func ProcessList(pid int, username, command, commandLine string) (list []ProcEntry) {
	items, err := getSystemProcessInformation()
	if err != nil {
		logging.Debugf("ProcessList: NtQuerySystemInformation: %v", err)
		return nil
	}

	for _, item := range items {
		pID := item.PID
		exePath := ProcExePath(pID)
		name := item.Name
		if exePath != "dead_process" && !strings.HasPrefix(exePath, "err_") {
			name = filepath.Base(exePath)
		}

		cmdline := ProcCmdline(pID)
		if cmdline == "dead_process" || strings.HasPrefix(cmdline, "err_") {
			cmdline = item.Name
		}

		token, uid := ProcUserAndSID(pID)

		p := ProcEntry{
			Name:      name,
			Cmdline:   cmdline,
			Token:     token,
			UID:       uid,
			Namespace: "",
			PID:       pID,
			PPID:      item.PPID,
		}

		// Apply filters
		if (pid == 0 || p.PID == pid) &&
			(username == "" || strings.EqualFold(p.Token, username) || strings.EqualFold(p.UID, username) || strings.Contains(strings.ToLower(p.Token), strings.ToLower(username))) &&
			(command == "" || strings.Contains(strings.ToLower(p.Name), strings.ToLower(command))) &&
			(commandLine == "" || strings.Contains(strings.ToLower(p.Cmdline), strings.ToLower(commandLine))) {
			list = append(list, p)
		}
	}
	return list
}

// ProcUserAndSID retrieves username and SID string for the given process ID on Windows
func ProcUserAndSID(pid int) (username string, sid string) {
	username = "unknown_user"
	sid = "N/A"

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		hProc, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
		if err != nil {
			return username, sid
		}
	}
	defer windows.CloseHandle(hProc)

	var token windows.Token
	err = windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return username, sid
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return username, sid
	}

	sid = tokenUser.User.Sid.String()

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err == nil {
		if domain != "" {
			username = fmt.Sprintf("%s\\%s", domain, account)
		} else {
			username = account
		}
	}

	return username, sid
}

// ProcUser retrieves username associated with the given process ID
func ProcUser(pid int) string {
	u, _ := ProcUserAndSID(pid)
	return u
}

// ProcExePath read executable path of a process on Windows
func ProcExePath(pid int) string {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		hProc, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
		if err != nil {
			if os.IsNotExist(err) || err == windows.ERROR_INVALID_PARAMETER {
				return "dead_process"
			}
			return fmt.Sprintf("err_%v", err)
		}
	}
	defer windows.CloseHandle(hProc)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size)
	if err != nil {
		return fmt.Sprintf("err_%v", err)
	}
	return windows.UTF16ToString(buf[:size])
}

// ProcCwd read working directory of a process on Windows via PEB
func ProcCwd(pid int) string {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		if os.IsNotExist(err) || err == windows.ERROR_INVALID_PARAMETER {
			return "dead_process"
		}
		return fmt.Sprintf("err_%v", err)
	}
	defer windows.CloseHandle(hProc)

	paramsPtr, err := getProcessParametersPtr(hProc)
	if err != nil {
		return fmt.Sprintf("err_%v", err)
	}

	cwdOffset := uintptr(0x38)
	if unsafe.Sizeof(cwdOffset) == 4 {
		cwdOffset = 0x24
	}

	cwd, err := readUnicodeString(hProc, paramsPtr+cwdOffset)
	if err != nil || strings.TrimSpace(cwd) == "" {
		return fmt.Sprintf("err_%v", err)
	}

	return cwd
}

// ProcCmdline read command line data of a process on Windows via PEB
func ProcCmdline(pid int) string {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		exe := ProcExePath(pid)
		if exe == "dead_process" || strings.HasPrefix(exe, "err_") {
			return "dead_process"
		}
		return exe
	}
	defer windows.CloseHandle(hProc)

	paramsPtr, err := getProcessParametersPtr(hProc)
	if err != nil {
		exe := ProcExePath(pid)
		if exe == "dead_process" || strings.HasPrefix(exe, "err_") {
			return "dead_process"
		}
		return exe
	}

	cmdOffset := uintptr(0x70)
	if unsafe.Sizeof(cmdOffset) == 4 {
		cmdOffset = 0x40
	}

	cmdline, err := readUnicodeString(hProc, paramsPtr+cmdOffset)
	if err != nil || strings.TrimSpace(cmdline) == "" {
		exe := ProcExePath(pid)
		if exe == "dead_process" || strings.HasPrefix(exe, "err_") {
			return "dead_process"
		}
		return exe
	}

	return cmdline
}

// IsPIDAlive check if a PID exists on Windows
func IsPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	items, err := getSystemProcessInformation()
	if err == nil {
		for _, item := range items {
			if item.PID == pid {
				return true
			}
		}
		return false
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err == windows.ERROR_ACCESS_DENIED
	}
	defer windows.CloseHandle(hProc)

	var exitCode uint32
	err = windows.GetExitCodeProcess(hProc, &exitCode)
	if err != nil {
		return false
	}
	return exitCode == 259 // STILL_ACTIVE
}

// IsProcAlive check if a process name exists, returns its process(es)
func IsProcAlive(procName string) (alive bool, procs []*ProcSimple) {
	items, err := getSystemProcessInformation()
	if err != nil {
		logging.Errorf("IsProcAlive: %v", err)
		return false, nil
	}

	for _, item := range items {
		if strings.EqualFold(item.Name, procName) || strings.EqualFold(filepath.Base(item.Name), procName) {
			alive = true
			if item.PID >= 0 && item.PID <= math.MaxInt32 {
				procs = append(procs, &ProcSimple{Pid: int32(item.PID)})
			}
		}
	}

	return alive, procs
}

// PidOf PID of a process name
func PidOf(name string) []int {
	pids := make([]int, 0)
	items, err := getSystemProcessInformation()
	if err != nil {
		logging.Errorf("PidOf: %v", err)
		return pids
	}

	for _, item := range items {
		if strings.EqualFold(item.Name, name) || strings.EqualFold(filepath.Base(item.Name), name) {
			pids = append(pids, item.PID)
		}
	}

	return pids
}

// GetChildren get children processes of a process on Windows
func GetChildren(pid int) (children []int, err error) {
	items, err := getSystemProcessInformation()
	if err != nil {
		logging.Debugf("GetChildren: %v", err)
		return nil, err
	}

	for _, item := range items {
		if item.PPID == pid {
			children = append(children, item.PID)
		}
	}
	return children, nil
}

func getProcessParametersPtr(hProc windows.Handle) (uintptr, error) {
	var pbi processBasicInformation
	var returnLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProc),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if status != 0 || pbi.PebBaseAddress == 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess status 0x%x", status)
	}

	pebOffset := uintptr(0x20)
	if unsafe.Sizeof(pebOffset) == 4 {
		pebOffset = 0x10
	}

	var processParametersPtr uintptr
	var readBytes uintptr
	err := windows.ReadProcessMemory(hProc, pbi.PebBaseAddress+pebOffset, (*byte)(unsafe.Pointer(&processParametersPtr)), unsafe.Sizeof(processParametersPtr), &readBytes)
	if err != nil || processParametersPtr == 0 {
		return 0, fmt.Errorf("ReadProcessMemory PEB: %v", err)
	}

	return processParametersPtr, nil
}

func readUnicodeString(hProc windows.Handle, addr uintptr) (string, error) {
	var uStrBuffer [16]byte
	var readBytes uintptr
	err := windows.ReadProcessMemory(hProc, addr, &uStrBuffer[0], uintptr(len(uStrBuffer)), &readBytes)
	if err != nil {
		return "", err
	}

	var length uint16
	var bufPtr uintptr
	if unsafe.Sizeof(bufPtr) == 8 {
		length = *(*uint16)(unsafe.Pointer(&uStrBuffer[0]))
		bufPtr = *(*uintptr)(unsafe.Pointer(&uStrBuffer[8]))
	} else {
		length = *(*uint16)(unsafe.Pointer(&uStrBuffer[0]))
		bufPtr = *(*uintptr)(unsafe.Pointer(&uStrBuffer[4]))
	}

	if length == 0 || bufPtr == 0 {
		return "", fmt.Errorf("empty unicode string")
	}

	utf16Buf := make([]uint16, length/2)
	err = windows.ReadProcessMemory(hProc, bufPtr, (*byte)(unsafe.Pointer(&utf16Buf[0])), uintptr(length), &readBytes)
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(utf16Buf), nil
}
