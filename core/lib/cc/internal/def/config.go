package def

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/cli"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// ActiveAgent selected target
	ActiveAgent *emp3r0r_def.Emp3r0rAgent

	// Save the configuration of the current session
	RuntimeConfig = &emp3r0r_def.Config{}
	// TmuxPersistence enable debug (-debug)
	TmuxPersistence = false
	// Prefix /usr or /usr/local, can be set through $EMP3R0R_PREFIX
	Prefix = ""
	// EmpWorkSpace workspace directory of emp3r0r
	EmpWorkSpace = ""
	// EmpDataDir prefix/lib/emp3r0r
	EmpDataDir = ""
	// EmpBuildDir prefix/lib/emp3r0r/build
	EmpBuildDir = ""
	// FileGetDir where we save #get files
	FileGetDir = ""
	// EmpConfigFile emp3r0r.json
	EmpConfigFile = ""
	// EmpLogFile emp3r0r.log
	EmpLogFile = ""

	// emp3r0r-cat
	CAT = ""

	// certs
	CACrtFile     string
	CAKeyFile     string
	ServerCrtFile string
	ServerKeyFile string
)

const (
	// Temp where we save temp files
	Temp = "/tmp/emp3r0r/"

	// WWWRoot host static files for agent
	WWWRoot = Temp + "www/"

	// UtilsArchive host utils.tar.xz for agent
	UtilsArchive = WWWRoot + "utils.tar.xz"
)

// InitCC set workspace, module directories, certs etc
func InitCC() (err error) {
	// prefix
	Prefix = os.Getenv("EMP3R0R_PREFIX")
	if Prefix == "" {
		Prefix = "/usr/local"
	}
	// eg. /usr/local/lib/emp3r0r
	EmpDataDir = Prefix + "/lib/emp3r0r"
	EmpBuildDir = EmpDataDir + "/build"
	CAT = EmpDataDir + "/emp3r0r-cat"

	if !util.IsExist(EmpDataDir) {
		return fmt.Errorf("emp3r0r is not installed correctly: %s not found", EmpDataDir)
	}
	if !util.IsExist(CAT) {
		return fmt.Errorf("emp3r0r is not installed correctly: %s not found", CAT)
	}

	// set workspace to ~/.emp3r0r
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %v", err)
	}
	EmpWorkSpace = u.HomeDir + "/.emp3r0r"
	FileGetDir = EmpWorkSpace + "/file-get/"
	EmpConfigFile = EmpWorkSpace + "/emp3r0r.json"
	EmpLogFile = EmpWorkSpace + "/emp3r0r.log"
	if !util.IsDirExist(EmpWorkSpace) {
		err = os.MkdirAll(FileGetDir, 0o700)
		if err != nil {
			return fmt.Errorf("mkdir %s: %v", EmpWorkSpace, err)
		}
	}

	// prefixes for stubs
	emp3r0r_def.Stub_Linux = EmpWorkSpace + "/stub"
	emp3r0r_def.Stub_Windows = EmpWorkSpace + "/stub-win"

	// copy stub binaries to ~/.emp3r0r
	stubFiles, err := filepath.Glob(fmt.Sprintf("%s/stub*", EmpBuildDir))
	if err != nil {
		return fmt.Errorf("finding agent stubs: %v", err)
	}
	for _, stubFile := range stubFiles {
		copyErr := util.Copy(stubFile, EmpWorkSpace)
		if copyErr != nil {
			return fmt.Errorf("copying agent stubs: %v", copyErr)
		}
	}

	// cd to workspace
	err = os.Chdir(EmpWorkSpace)
	if err != nil {
		return fmt.Errorf("cd to workspace %s: %v", EmpWorkSpace, err)
	}

	// Module directories
	ModuleDirs = []string{EmpDataDir + "/modules", EmpWorkSpace + "/modules"}

	// cert files
	CACrtFile = tun.CA_CERT_FILE
	CAKeyFile = tun.CA_KEY_FILE
	ServerCrtFile = tun.ServerCrtFile
	ServerKeyFile = tun.ServerKeyFile

	// certs
	err = init_certs_config()
	if err != nil {
		return fmt.Errorf("init_certs_config: %v", err)
	}

	return
}

func ReadJSONConfig() (err error) {
	// read JSON
	jsonData, err := os.ReadFile(EmpConfigFile)
	if err != nil {
		return
	}

	return emp3r0r_def.ReadJSONConfig(jsonData, RuntimeConfig)
}

// re-generate a random magic string for this CC session
func InitMagicAgentOneTimeBytes() {
	default_magic_str := emp3r0r_def.OneTimeMagicBytes
	emp3r0r_def.OneTimeMagicBytes = util.RandBytes(len(default_magic_str))

	// update binaries
	files, err := os.ReadDir(EmpWorkSpace)
	if err != nil {
		logging.Fatalf("init_magic_str: %v", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name(), "stub-") {
			err = util.ReplaceBytesInFile(fmt.Sprintf("%s/%s", EmpWorkSpace, f.Name()),
				default_magic_str, emp3r0r_def.OneTimeMagicBytes)
			if err != nil {
				logging.Fatalf("init_magic_str: %v", err)
			}
		}
	}
}

// init_certs_config generate certs if not found
func init_certs_config() error {
	if _, err := os.Stat(CACrtFile); os.IsNotExist(err) {
		logging.Warningf("CA cert not found, generating a new one")
		_, err := tun.GenCerts(nil, CACrtFile, CAKeyFile, true)
		if err != nil {
			return fmt.Errorf("GenCerts: %v", err)
		}
	}

	// generate C2 TLS cert for given host names
	var hosts []string
	if _, err := os.Stat(ServerKeyFile); os.IsNotExist(err) {
		logging.Warningf("C2 TLS cert not found, generating a new one")
		input := cli.Prompt("Generate C2 TLS cert for host IPs or names (space separated)")
		if strings.Contains(input, "/") || strings.Contains(input, "\\") {
			return fmt.Errorf("invalid host names")
		}
		hosts = strings.Fields(input)
		hosts = append(hosts, "127.0.0.1") // sometimes we need to connect to a relay that listens on localhost
		hosts = append(hosts, "localhost") // sometimes we need to connect to a relay that listens on localhost
		_, certErr := tun.GenCerts(hosts, ServerCrtFile, ServerKeyFile, false)
		if certErr != nil {
			return certErr
		}
	} else {
		hosts = tun.NamesInCert(ServerCrtFile)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no host names found in C2 TLS cert")
	}

	err := LoadCACrt2RuntimeConfig()
	if err != nil {
		return fmt.Errorf("failed to load CA to RuntimeConfig: %v", err)
	}

	// init config file using the first host name
	certErr := InitConfigFile(hosts[0])
	if certErr != nil {
		return fmt.Errorf("%s: %v", EmpConfigFile, certErr)
	}
	return nil
}
