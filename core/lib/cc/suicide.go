//go:build linux
// +build linux

package cc


func Suicide() {
	SendCmdToCurrentTarget("suicide", "")
}
