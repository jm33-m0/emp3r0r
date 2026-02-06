//go:build !linux
// +build !linux

package handler

import "github.com/spf13/cobra"

func GetLinuxSpecificCmds() []*cobra.Command {
	return []*cobra.Command{}
}
