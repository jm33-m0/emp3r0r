//go:build windows
// +build windows

package agent

import (
	"fmt"
	"log"
	"unsafe"

	"github.com/gonutz/w32/v2"
	"golang.org/x/sys/windows"
)

// see https://gist.github.com/SCP002/ab863ef9ffbacedc2c0b1b4d30e80805
var (
	Kernel32DLL = windows.NewLazyDLL("kernel32.dll")
)

// IsMainWindow returns true if a window with the specified handle is a main window.
func IsMainWindow(hwnd w32.HWND) bool {
	// return w32.GetWindow(hwnd, w32.GW_OWNER) == 0 && w32.IsWindowVisible(hwnd)
	return w32.GetWindow(hwnd, w32.GW_OWNER) == 0
}

// GetWindowHandleByPID returns main window handle of the process.
//
// If "allowOwnConsole" is set to "true", allow to return own console window of the process.
//
// Inspired by https://stackoverflow.com/a/21767578.
func GetWindowHandleByPID(pid int, allowOwnConsole bool) (w32.HWND, error) {
	var wnd w32.HWND
	callback_func := func(hwnd w32.HWND) bool {
		_, currentPid := w32.GetWindowThreadProcessId(hwnd)

		if int(currentPid) == pid && IsMainWindow(hwnd) {
			wnd = hwnd
			// Stop enumerating.
			log.Printf("GetWindowHandleByPID: %d matches", currentPid)
			return false
		}
		// Continue enumerating.
		return true
	}
	w32.EnumWindows(callback_func)
	if wnd != 0 {
		return wnd, nil
	}
	if allowOwnConsole {
		if attached, _ := IsAttachedToCaller(pid); attached {
			return w32.GetConsoleWindow(), nil
		}
	}
	return wnd, fmt.Errorf("No window found for PID %d", pid)
}

// IsAttachedToCaller returns true if the given PID is attached to the current console.
func IsAttachedToCaller(pid int) (bool, error) {
	pids, err := GetConsolePids(1)
	if err != nil {
		return false, err
	}
	for _, currentPid := range pids {
		if currentPid == uint32(pid) {
			return true, nil
		}
	}
	return false, nil
}

// GetConsolePids returns a slice of PID's attached to the current console.
//
// pidsLen parameter - the maximum number of PID's that can be stored in buffer.
// Must be > 0. Can be increased automatically (safe to pass 1).
//
// See https://docs.microsoft.com/en-us/windows/console/getconsoleprocesslist.
func GetConsolePids(pidsLen int) ([]uint32, error) {
	k32Proc := Kernel32DLL.NewProc("GetConsoleProcessList")

	pids := make([]uint32, pidsLen)
	r1, _, err := k32Proc.Call(
		// Actually passing the whole slice. Must be [0] due the way syscall works.
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(pidsLen),
	)
	if r1 == 0 {
		return pids, err
	}
	if r1 <= uintptr(pidsLen) {
		// Success, return the slice.
		return pids, nil
	} else {
		// The initial buffer was too small. Call self again with the exact capacity.
		return GetConsolePids(int(r1))
	}
}

// SetWinsize resize main window of given process
// w/h: width/height in pixels
// window position resets to 0, 0
func SetWinsize(pid, w, h int) {
	whandle, err := GetWindowHandleByPID(pid, true)
	if err != nil {
		log.Printf("SetWinsize: %v", err)
		return
	}
	w_px := w * (16 / 72) * 96
	h_px := h * (16 / 72) * 96
	if w32.SetWindowPos(whandle, whandle, 0, 0, w_px, h_px, w32.SWP_NOMOVE|w32.SWP_NOZORDER) {
		log.Printf("Window (0x%x) of %d has been resized to %dx%d (chars)",
			whandle, pid, w, h)
	}
}

func SetConsoleBufferSize(pid, w, h int) {
	coord := w32.COORD{
		X: int16(w),
		Y: int16(h),
	}
	set_console_buffer_size := Kernel32DLL.NewProc("SetConsoleScreenBufferSize")
	var console_output_handle windows.Handle

	// TODO obtain handle of console buffer output

	_, _, err := set_console_buffer_size.Call(
		uintptr(unsafe.Pointer(&console_output_handle)),
		uintptr(unsafe.Pointer(&coord)))

	if err != nil {
		log.Printf("SetConsoleBufferSize failed: %v", err)
	}
}
