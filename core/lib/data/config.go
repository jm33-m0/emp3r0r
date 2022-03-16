package emp3r0r_data

import (
	"encoding/json"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

func ReadJSONConfig(jsonData []byte) (err error) {
	// parse the json
	err = json.Unmarshal(jsonData, RuntimeConfig)
	if err != nil {
		return fmt.Errorf("failed to parse JSON config: %v", err)
	}

	// set up runtime vars
	SSHDPort = RuntimeConfig.SSHDPort
	BroadcastPort = RuntimeConfig.BroadcastPort
	ProxyPort = RuntimeConfig.ProxyPort
	CCPort = RuntimeConfig.CCPort
	CCAddress = fmt.Sprintf("https://%s", RuntimeConfig.CCIP)

	// CA
	tun.CACrt = []byte(RuntimeConfig.CA)

	return
}
