//go:build !cgo
// +build !cgo

package main

func main() {
	// run main function
	agent_main()
}

// we need to know if we are a DLL or standalone executable
func IsDLL() bool {
	return false
}
