//go:build windows

package driver

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNTPathFromWin32(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"drive letter", `C:\Windows\System32\drivers\foo.sys`, `\??\C:\Windows\System32\drivers\foo.sys`},
		{"device prefix", `\\?\C:\foo.sys`, `\??\C:\foo.sys`},
		{"unc", `\\server\share\foo.sys`, `\??\UNC\server\share\foo.sys`},
		{"already nt", `\??\C:\foo.sys`, `\??\C:\foo.sys`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ntPathFromWin32(tt.in); got != tt.want {
				t.Errorf("ntPathFromWin32(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUnicodeString(t *testing.T) {
	us := newUnicodeString(`\Registry\Machine\System\CurrentControlSet\Services\test`)
	want := `\Registry\Machine\System\CurrentControlSet\Services\test`
	if int(us.Length) != len(want)*2 {
		t.Errorf("Length = %d, want %d", us.Length, len(want)*2)
	}
	if int(us.MaximumLength) != (len(want)+1)*2 {
		t.Errorf("MaximumLength = %d, want %d", us.MaximumLength, (len(want)+1)*2)
	}
	if got := windows.UTF16ToString(us.keepalive[:len(us.keepalive)-1]); got != want {
		t.Errorf("Buffer = %q, want %q", got, want)
	}
}

// TestIsDriverSigned verifies WinVerifyTrust against files that are signed
// on every stock Windows installation.
func TestIsDriverSigned(t *testing.T) {
	candidates := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "kbdclass.sys"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "mountmgr.sys"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "ntoskrnl.exe"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll"),
	}
	path := ""
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no known-signed system file found")
	}

	signed, err := IsDriverSigned(path)
	if err != nil {
		t.Fatalf("IsDriverSigned(%s): %v", path, err)
	}
	if !signed {
		t.Errorf("expected %s to verify as signed", path)
	}
}

// TestLoadUnloadRoundTrip performs a real load/unload cycle. It is gated
// behind EMP3R0R_TEST_DRIVER_PATH (path to a signed test .sys) because it
// requires administrator privileges and a usable driver image; CI runs it
// only when explicitly configured.
func TestLoadUnloadRoundTrip(t *testing.T) {
	driverPath := os.Getenv("EMP3R0R_TEST_DRIVER_PATH")
	if driverPath == "" {
		t.Skip("set EMP3R0R_TEST_DRIVER_PATH to a signed test driver to enable")
	}
	const serviceName = "emp3r0r_test_driver"

	if IsLoaded(serviceName) {
		if err := UnloadDriver(serviceName); err != nil {
			t.Fatalf("pre-cleanup UnloadDriver: %v", err)
		}
	}

	if err := LoadSignedDriver(driverPath, serviceName); err != nil {
		t.Fatalf("LoadSignedDriver: %v", err)
	}
	if !IsLoaded(serviceName) {
		t.Error("driver service not registered after load")
	}
	if err := UnloadDriver(serviceName); err != nil {
		t.Fatalf("UnloadDriver: %v", err)
	}
	if IsLoaded(serviceName) {
		t.Error("driver service still registered after unload")
	}
}

func TestIsLoadedEmpty(t *testing.T) {
	if IsLoaded("") {
		t.Error("IsLoaded(\"\") should be false")
	}
}
