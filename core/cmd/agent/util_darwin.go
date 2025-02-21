//go:build darwin
// +build darwin

package main

import "log"

// Dummy implementation for darwin build

func socketListen() {
	log.Println("socketListen dummy for darwin")
}
