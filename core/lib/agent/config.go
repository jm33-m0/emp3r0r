package agent

import (
	"fmt"
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var RuntimeConfig = &emp3r0r_data.Config{}

func ApplyRuntimeConfig() (err error) {
	encJsonData, err := util.DigEmbeddedDataFromArg0()
	if err != nil {
		e := err
		log.Printf("read config from file: %v", err)
		encJsonData, err = util.DigEmbededDataFromMem()
		if err != nil {
			return fmt.Errorf("read config from file: %v. from memory: %v", e, err)
		}
	}

	// decrypt attached JSON file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	decJsonData := tun.AESDecryptRaw(key, encJsonData)
	if decJsonData == nil {
		err = fmt.Errorf("Decrypt JSON with key %s failed", key)
		return
	}

	// parse JSON
	err = emp3r0r_data.ReadJSONConfig(decJsonData, RuntimeConfig)
	if err != nil {
		short_view := decJsonData
		if len(decJsonData) > 100 {
			short_view = decJsonData[:100]
		}
		return fmt.Errorf("parsing %d bytes of JSON data (%s...): %v", len(decJsonData), short_view, err)
	}

	// CA
	tun.CACrt = []byte(RuntimeConfig.CA)
	return
}
