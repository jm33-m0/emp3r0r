//go:build linux
// +build linux

package cc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

func UpgradeAgent(cmd *cobra.Command, args []string) {
	if !util.IsExist(WWWRoot + "agent") {
		LogError("%s/agent not found, build one with `use gen_agent` first", WWWRoot)
		return
	}
	checksum := tun.SHA256SumFile(WWWRoot + "agent")
	SendCmdToCurrentTarget(fmt.Sprintf("%s --checksum %s", emp3r0r_def.C2CmdUpdateAgent, checksum), "")
}

// read config by key from emp3r0r.json
func read_cached_config(config_key string) (val interface{}) {
	// read existing config when possible
	var config_map map[string]interface{}

	if util.IsExist(EmpConfigFile) {
		LogDebug("Reading config '%s' from existing %s", config_key, EmpConfigFile)
		jsonData, err := os.ReadFile(EmpConfigFile)
		if err != nil {
			LogWarning("failed to read %s: %v", EmpConfigFile, err)
			return ""
		}
		// load to map
		err = json.Unmarshal(jsonData, &config_map)
		if err != nil {
			LogWarning("Parsing existing %s: %v", EmpConfigFile, err)
			return ""
		}
	}
	val, exists := config_map[config_key]
	if !exists {
		LogWarning("%s not found in JSON config", config_key)
		return ""
	}
	return val
}

// GenC2Certs generate certificates for CA and emp3r0r C2 server
func GenC2Certs(hosts []string) (err error) {
	if !util.IsFileExist(CAKeyFile) || !util.IsFileExist(CACrtFile) {
		LogMsg("CA cert not found, generating...")
		_, err = tun.GenCerts(nil, "", true)
		if err != nil {
			return fmt.Errorf("generate CA: %v", err)
		}
		LogInfo("CA fingerprint: %s", RuntimeConfig.CAFingerprint)
	}

	// save CA cert to emp3r0r.json
	err = LoadCACrt()
	if err != nil {
		return fmt.Errorf("GenC2Certs failed to load CA to RuntimeConfig: %v", err)
	}

	// generate server cert
	LogMsg("Server cert not found, generating...")
	LogInfo("Server cert fingerprint: %s", tun.GetFingerprint(ServerCrtFile))
	_, err = tun.GenCerts(hosts, "emp3r0r", false)
	return
}

func save_config_json() (err error) {
	err = LoadCACrt()
	if err != nil {
		return fmt.Errorf("save_config_json: %v", err)
	}
	w_data, err := json.Marshal(RuntimeConfig)
	if err != nil {
		return fmt.Errorf("saving %s: %v", EmpConfigFile, err)
	}

	return os.WriteFile(EmpConfigFile, w_data, 0o600)
}

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

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	// CA cert
	ca_data, err := os.ReadFile(CACrtFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
	}
	tun.CACrt = ca_data
	RuntimeConfig.CAPEM = string(tun.CACrt)
	RuntimeConfig.CAFingerprint = tun.GetFingerprint(CACrtFile)
	return nil
}
