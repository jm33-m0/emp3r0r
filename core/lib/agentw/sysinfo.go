package agentw

//build +windows

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"unsafe"

	def "github.com/jm33-m0/emp3r0r/core/lib/data"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type OSInfo struct {
	Name         string
	Version      string
	Architecture string
}

func GetOSInfo() *OSInfo {
	osinfo := OSInfo{}
	osinfo.Name = OSVersion()
	osinfo.Version = GetKernelVersion()
	osinfo.Architecture = runtime.GOARCH
	return &osinfo
}

func OSVersion() (platform string) {
	var err error

	platform = "Microsoft Windows"
	log.Println("Reading OS version...")

	// Platform
	var h windows.Handle // like HostIDWithContext(), we query the registry using the raw windows.RegOpenKeyEx/RegQueryValueEx
	err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`), 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h)
	if err != nil {
		return
	}
	defer func() {
		err := windows.RegCloseKey(h)
		if err != nil {
			log.Printf("RegCloseKey: %v", err)
		}
	}()
	var bufLen uint32
	var valType uint32
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`ProductName`), nil, &valType, nil, &bufLen)
	if err != nil {
		return
	}
	regBuf := make([]uint16, bufLen/2+1)
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`ProductName`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
	if err != nil {
		return
	}
	platform = windows.UTF16ToString(regBuf[:])
	if !strings.HasPrefix(platform, "Microsoft") {
		platform = "Microsoft " + platform
	}
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`CSDVersion`), nil, &valType, nil, &bufLen) // append Service Pack number, only on success
	if err == nil {                                                                                       // don't return an error if only the Service Pack retrieval fails
		regBuf = make([]uint16, bufLen/2+1)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`CSDVersion`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err == nil {
			platform += " " + windows.UTF16ToString(regBuf[:])
		}
	}

	return
}

func GetKernelVersion() (ver string) {
	log.Println("Reading kernel version...")
	ver = def.Unknown
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		log.Print(err)
		return
	}
	defer k.Close()

	cv, _, err := k.GetStringValue("CurrentVersion")
	if err != nil {
		log.Print(err)
		return
	}
	ver = cv

	maj, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		log.Print(err)
		return
	}
	ver = fmt.Sprintf("%s, NT %d", ver, maj)

	min, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		log.Print(err)
		return
	}
	ver = fmt.Sprintf("%s.%d", ver, min)

	cb, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		log.Print(err)
		return
	}
	ver = fmt.Sprintf("%s, build %s", ver, cb)

	return
}

// IsPrivileged is current user privileged?
func IsPrivileged() (result bool) {
	token := windows.Token(0) // current user

	return IsUserPrivileged(token)
}

// Given a user token, check if it's privileged
func IsUserPrivileged(token windows.Token) (result bool) {
	var sid *windows.SID

	// Although this looks scary, it is directly copied from the
	// official windows documentation. The Go API for this is a
	// direct wrap around the official C++ API.
	// See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		log.Printf("SID Error: %s", err)
		return false
	}
	result, err = token.IsMember(sid)
	if err != nil {
		log.Printf("Token Membership Error: %s", err)
		return
	}

	return result || token.IsElevated()
}
