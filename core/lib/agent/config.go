package agent

import (
	"encoding/base64"
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var RuntimeConfig = &emp3r0r_data.Config{}

func ApplyRuntimeConfig() (err error) {
	readJsonData, err := util.ExtractData()
	if err != nil {
		return fmt.Errorf("read config: %v", err)
	}

	// base64 decode
	decoded_json_data, err := base64.StdEncoding.DecodeString(string(readJsonData))
	if err != nil {
		return fmt.Errorf("ApplyRuntimeConfig: base64 decode: %v", err)
	}

	// decrypt attached JSON file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	jsonData := tun.AESDecryptRaw(key, decoded_json_data)
	if jsonData == nil {
		err = fmt.Errorf("Decrypt JSON with key %s failed", key)
		return
	}

	// parse JSON
	err = emp3r0r_data.ReadJSONConfig(jsonData, RuntimeConfig)
	if err != nil {
		short_view := jsonData
		if len(jsonData) > 100 {
			short_view = jsonData[:100]
		}
		return fmt.Errorf("parsing %d bytes of JSON data (%s...): %v", len(jsonData), short_view, err)
	}

	// CA
	tun.CACrt = []byte(RuntimeConfig.CA)
	return
}
