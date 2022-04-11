//go:build windows
// +build windows

package agent

import (
	"fmt"
	"log"
	"unsafe"

	"github.com/gonutz/w32/v2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// see https://gist.github.com/SCP002/ab863ef9ffbacedc2c0b1b4d30e80805
var (
	Kernel32DLL        = windows.NewLazyDLL("kernel32.dll")
	ConsoleExtraWidth  = 0 // scroll bar, etc
	ConsoleExtraHeight = 0 // title bar
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

// SetCosoleWinsize resize main window of given console process
// w/h: width/height in characters
// window position resets to 0, 0 (pixel)
func SetCosoleWinsize(pid, w, h int) {
	whandle, err := GetWindowHandleByPID(pid, true)
	if err != nil {
		log.Printf("SetWinsize: %v", err)
		return
	}
	// read default font size from registry
	console_reg_key, err := registry.OpenKey(registry.CURRENT_USER, "Console", registry.QUERY_VALUE)
	if err != nil {
		log.Printf("SetCosoleWinsize: %v", err)
		return
	}
	defer console_reg_key.Close()
	font_size_val, _, err := console_reg_key.GetIntegerValue("FontSize")
	if err != nil {
		log.Printf("SetConsoleWinSize: query fontsize: %v", err)
		return
	}
	font_size := int(font_size_val >> 16) // font height in pixels, width = h/2
	log.Printf("Default font size of console host is %d (0x%x), parsed from 0x%x",
		font_size, font_size, font_size_val)
	// what size in pixels we need
	w_px := w * font_size / 2
	h_px := h * font_size

	if ConsoleExtraHeight == 0 && ConsoleExtraWidth == 0 {
		// Get default window size
		now_size, _, err := console_reg_key.GetIntegerValue("WindowSize")
		if err != nil {
			log.Printf("window size: %v", err)
			return
		}
		// in chars
		default_width := int(now_size & 0xffff)
		default_height := int(now_size >> 16)
		// in pixels
		default_w_px := default_width * font_size / 2
		default_h_px := default_height * font_size
		log.Printf("Default window (client rectangle) is %dx%d (chars) or %dx%d (pixels)",
			default_width, default_height,
			default_w_px, default_h_px)
		// window size in pixels, including title bar and frame
		now_rect := w32.GetWindowRect(whandle)
		now_w_px := int(now_rect.Width())
		now_h_px := int(now_rect.Height())
		if now_h_px <= 0 || now_w_px <= 0 {
			log.Printf("Now window (normal rectangle) size is %dx%d, aborting", now_w_px, now_h_px)
			return
		}
		// calculate extra width and height
		ConsoleExtraHeight = now_h_px - default_h_px
		ConsoleExtraWidth = now_w_px - default_w_px
		if ConsoleExtraWidth <= 0 || ConsoleExtraHeight <= 0 {
			log.Printf("Extra width %d, extra height %d, aborting", ConsoleExtraWidth, ConsoleExtraHeight)
			return
		}

	}
	w_px = w_px + ConsoleExtraWidth
	h_px = h_px + ConsoleExtraHeight

	// set window size in pixels
	if w32.SetWindowPos(whandle, whandle, 0, 0, w_px, h_px, w32.SWP_NOMOVE|w32.SWP_NOZORDER) {
		log.Printf("Window (0x%x) of %d has been resized to %dx%d (chars) or %dx%d (pixels)",
			whandle, pid, w, h, w_px, h_px)
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
