package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/packer/internal/utils"
	"github.com/mholt/archiver"
)

func main() {
	inputELF := flag.String("input", "./agent", "The ELF file to pack")
	flag.Parse()

	// read file
	elfBytes, err := ioutil.ReadFile(*inputELF)
	if err != nil {
		log.Fatal(err)
	}
	origSize := float32(len(elfBytes))
	log.Printf("ELF size: %d bytes", int(origSize))
	var compressedBytes []byte

	// compress
	gz := &archiver.Gz{CompressionLevel: 9}
	r, err := os.Open(*inputELF)
	if err != nil {
		log.Fatal(err)
	}
	bufCompress := bytes.NewBuffer(compressedBytes)
	err = gz.Compress(r, bufCompress)
	if err != nil {
		log.Fatal(err)
	}
	newSize := float32(bufCompress.Len())
	log.Printf("ELF compressed: %d bytes (%.2f%%)", int(newSize), newSize/origSize)

	// encrypt
	key := utils.GenAESKey(utils.Key)
	encELFBytes := utils.AESEncrypt(key, bufCompress.Bytes())
	if encELFBytes == nil {
		log.Fatalf("failed to encrypt %s", *inputELF)
	}

	// build stub
	err = os.Chdir("./cmd/stub")
	if err != nil {
		log.Fatal(err)
	}
	out, err := exec.Command("go", "build", "-ldflags=-s -w", "-o", "../../stub.exe").CombinedOutput()
	if err != nil {
		log.Fatalf("go build failed: %v\n%s", err, out)
	}
	err = os.Chdir("../../")
	if err != nil {
		log.Fatal(err)
	}

	// write
	toWrite, err := ioutil.ReadFile("stub.exe")
	if err != nil {
		log.Fatal(err)
	}
	toWrite = append(toWrite, []byte(utils.Sep)...)
	toWrite = append(toWrite, encELFBytes...)
	err = ioutil.WriteFile(fmt.Sprintf("%s.packed.exe", *inputELF), toWrite, 0600)
	if err != nil {
		log.Fatal(err)
	}

	// done
	os.Remove(*inputELF)
	log.Printf("%s has been packed as %s.packed.exe", *inputELF, *inputELF)
}
