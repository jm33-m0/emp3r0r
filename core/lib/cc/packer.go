//go:build linux
// +build linux

package cc

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver/v3"
)

func upx(bin_to_pack, outfile string) (err error) {
	if !util.IsCommandExist("upx") {
		return fmt.Errorf("upx not found in your $PATH, please install it first")
	}
	CliPrintInfo("Using UPX to compress the executable %s", bin_to_pack)
	cmd := exec.Command("upx", "-9", bin_to_pack, "-o", outfile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("UPX: %s (%v)", out, err)
	}

	return
}
