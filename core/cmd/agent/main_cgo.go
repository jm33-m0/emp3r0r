//go:build cgo
// +build cgo

package main

import "C"

//export main
func main() {
	// run main function
	agent_main()
}
