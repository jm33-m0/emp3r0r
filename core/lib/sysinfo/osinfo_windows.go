//go:build windows
// +build windows

package sysinfo

import (
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"runtime"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func GetOSInfo() *OSInfo {
	osinfo := OSInfo{}
	osinfo.Name = getOSName()
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
		logging.Printf("isWow64Process: %v", err)
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

func getOSName() string {
	current_ver_key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		logging.Printf("getOSRelease: open key: %v", err)
	}
	defer current_ver_key.Close()
	product_name, _, err := current_ver_key.GetStringValue(`ProductName`)
	if err != nil {
		logging.Printf("product name: %v", err)
		product_name = "Unknown_Product"
	}
	owner, _, err := current_ver_key.GetStringValue(`RegisteredOwner`)
	if err != nil {
		logging.Printf("registered owner: %v", err)
		product_name = "Unknown_Owner"
	}
	install_date_unix, _, err := current_ver_key.GetIntegerValue(`InstallDate`)
	if err != nil {
		logging.Printf("install date: %v", err)
		install_date_unix = 0
	}
	install_time := time.Unix(int64(install_date_unix), 0)

	return fmt.Sprintf("%s (registered to %s on %v)", product_name, owner, install_time)
}

func GetKernelVersion() (ver string) {
	logging.Println("Reading kernel version...")
	ver = def.Unknown
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		logging.Print(err)
		return
	}
	defer k.Close()

	cv, _, err := k.GetStringValue("CurrentVersion")
	if err != nil {
		logging.Print(err)
		return
	}
	ver = cv

	maj, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		logging.Print(err)
		return
	}
	ver = fmt.Sprintf("%s, NT %d", ver, maj)

	min, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		logging.Print(err)
		return
	}
	ver = fmt.Sprintf("%s.%d", ver, min)

	cb, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		logging.Print(err)
		return
	}
	buildlab_ex, _, err := k.GetStringValue("BuildLabEx")
	if err != nil {
		logging.Printf("buildLabEx: %v", err)
		buildlab_ex = cb
	}

	ver = fmt.Sprintf("%s, build %s", ver, buildlab_ex)

	return
}
