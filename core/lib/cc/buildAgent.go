package cc

import (
	"io/ioutil"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

func GenAgent() {
	buildJSONFile := "./build.json"
	stubFile := "./stub.exe"
	CliPrintWarning("Make sure ./%s and ./%s exist", buildJSONFile, stubFile)

	// read file
	jsonBytes, err := ioutil.ReadFile(buildJSONFile)
	if err != nil {
		CliPrintError("%v", err)
		return
	}

	// encrypt
	key := tun.GenAESKey(agent.OpSep)
	encJSONBytes := tun.AESEncryptRaw(key, jsonBytes)
	if encJSONBytes == nil {
		CliPrintError("Failed to encrypt %s", buildJSONFile)
		return
	}

	// write
	toWrite, err := ioutil.ReadFile(stubFile)
	if err != nil {
		CliPrintError("%v", err)
		return
	}
	toWrite = append(toWrite, []byte(agent.OpSep)...)
	toWrite = append(toWrite, encJSONBytes...)
	err = ioutil.WriteFile("packed.exe", toWrite, 0755)
	if err != nil {
		CliPrintError("%v", err)
		return
	}

	// done
	CliPrintSuccess("Generated packed.exe")
}
