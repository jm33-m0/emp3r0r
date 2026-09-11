//go:build cgo && !emp3r0r_so

package main

import "C"

func main() {
	agent_main()
}
