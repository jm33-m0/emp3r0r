package agent

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

var RuntimeConfig = &emp3r0r_data.Config{}

func ApplyRuntimeConfig() (err error) {
	wholeStub, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		return
	}

	// locate the JSON file
	jsonBegining := bytes.LastIndex(wholeStub, []byte(emp3r0r_data.MagicString))
	jsonBytes := wholeStub[(jsonBegining + len(emp3r0r_data.MagicString)):]

	// decrypt attached JSON file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	jsonData := tun.AESDecryptRaw(key, jsonBytes)
	if jsonData == nil {
		err = fmt.Errorf("Decrypt JSON with key %s failed", key)
		return
	}

	// parse JSON
	err = emp3r0r_data.ReadJSONConfig(jsonData, RuntimeConfig)
	if err != nil {
		return fmt.Errorf("parsing JSON data (%s): %v", jsonData, err)
	}

	// CA
	tun.CACrt = []byte(RuntimeConfig.CA)
	log.Printf("CACrt:\n%s", tun.CACrt)
	return
}
