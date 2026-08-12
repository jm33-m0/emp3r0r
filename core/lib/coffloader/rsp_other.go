//go:build !windows || !amd64

package coffloader

var currentSavedRSP uintptr

func callBOF(entryPoint, argPtr, argLen uintptr) {
}
