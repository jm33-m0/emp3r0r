//go:build windows

package script

import (
	"fmt"
	"syscall"
	"unsafe"

	"go.starlark.net/starlark"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetTickCount64             = kernel32.NewProc("GetTickCount64")
	procGetLocalTime               = kernel32.NewProc("GetLocalTime")
	procGetSystemDefaultLocaleName = kernel32.NewProc("GetSystemDefaultLocaleName")
	procGetLocaleInfoEx            = kernel32.NewProc("GetLocaleInfoEx")
	procLocaleNameToLCID           = kernel32.NewProc("LocaleNameToLCID")
	procGetDateFormatEx            = kernel32.NewProc("GetDateFormatEx")
	procGetEnvironmentStringsW     = kernel32.NewProc("GetEnvironmentStringsW")
	procFreeEnvironmentStringsW    = kernel32.NewProc("FreeEnvironmentStringsW")
)

type systemtime struct {
	wYear         uint16
	wMonth        uint16
	wDayOfWeek    uint16
	wDay          uint16
	wHour         uint16
	wMinute       uint16
	wSecond       uint16
	wMilliseconds uint16
}

func starlarkGetTickCount64(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	ret, _, _ := procGetTickCount64.Call()
	return starlark.MakeInt64(int64(ret)), nil
}

func starlarkGetLocalTime(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var st systemtime
	procGetLocalTime.Call(uintptr(unsafe.Pointer(&st)))

	res := starlark.NewDict(6)
	res.SetKey(starlark.String("year"), starlark.MakeInt(int(st.wYear)))
	res.SetKey(starlark.String("month"), starlark.MakeInt(int(st.wMonth)))
	res.SetKey(starlark.String("day"), starlark.MakeInt(int(st.wDay)))
	res.SetKey(starlark.String("hour"), starlark.MakeInt(int(st.wHour)))
	res.SetKey(starlark.String("minute"), starlark.MakeInt(int(st.wMinute)))
	res.SetKey(starlark.String("second"), starlark.MakeInt(int(st.wSecond)))
	return res, nil
}

func starlarkGetSystemDefaultLocaleName(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	buf := make([]uint16, 85)
	r, _, _ := procGetSystemDefaultLocaleName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r == 0 {
		return starlark.None, fmt.Errorf("GetSystemDefaultLocaleName failed")
	}
	return starlark.String(syscall.UTF16ToString(buf)), nil
}

func starlarkGetLocaleInfoEx(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var localeName string
	var lcType int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "locale_name", &localeName, "lc_type", &lcType); err != nil {
		return starlark.None, err
	}

	localeNamePtr, err := syscall.UTF16PtrFromString(localeName)
	if err != nil {
		return starlark.None, err
	}

	buf := make([]uint16, 85)
	r, _, _ := procGetLocaleInfoEx.Call(
		uintptr(unsafe.Pointer(localeNamePtr)),
		uintptr(lcType),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r == 0 {
		return starlark.None, fmt.Errorf("GetLocaleInfoEx failed")
	}
	return starlark.String(syscall.UTF16ToString(buf)), nil
}

func starlarkLocaleNameToLCID(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var localeName string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "locale_name", &localeName); err != nil {
		return starlark.None, err
	}

	localeNamePtr, err := syscall.UTF16PtrFromString(localeName)
	if err != nil {
		return starlark.None, err
	}

	lcid, _, _ := procLocaleNameToLCID.Call(
		uintptr(unsafe.Pointer(localeNamePtr)),
		0,
	)
	if lcid == 0 {
		return starlark.None, fmt.Errorf("LocaleNameToLCID failed")
	}
	return starlark.MakeInt(int(lcid)), nil
}

func starlarkGetDateFormatEx(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var localeName string
	var dwFlags int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "locale_name", &localeName, "dw_flags", &dwFlags); err != nil {
		return starlark.None, err
	}

	localeNamePtr, err := syscall.UTF16PtrFromString(localeName)
	if err != nil {
		return starlark.None, err
	}

	buf := make([]uint16, 85)
	r, _, _ := procGetDateFormatEx.Call(
		uintptr(unsafe.Pointer(localeNamePtr)),
		uintptr(dwFlags),
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if r == 0 {
		return starlark.None, fmt.Errorf("GetDateFormatEx failed")
	}
	return starlark.String(syscall.UTF16ToString(buf)), nil
}

func starlarkGetEnvironmentStrings(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	r, _, _ := procGetEnvironmentStringsW.Call()
	if r == 0 {
		return starlark.None, fmt.Errorf("GetEnvironmentStringsW failed")
	}
	defer procFreeEnvironmentStringsW.Call(r)

	ptr := (*uint16)(unsafe.Pointer(r))
	envList := starlark.NewList(nil)

	for {
		if *ptr == 0 {
			break
		}
		var buf []uint16
		for {
			val := *ptr
			if val == 0 {
				break
			}
			buf = append(buf, val)
			ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2))
		}
		envList.Append(starlark.String(syscall.UTF16ToString(buf)))
		ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2))
	}
	return envList, nil
}
