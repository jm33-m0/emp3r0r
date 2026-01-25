package live

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/arc/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// IsServer is true if we are running as server
	IsServer = false

	// HOME is the user's home directory
	HOME = ""

	// ActiveAgent selected target
	ActiveAgent *def.Emp3r0rAgent

	// Save the configuration of the current session
	RuntimeConfig = &def.Config{}
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
	// EmpLogFile ~/.emp3r0r/emp3r0r.log, initialized in logging package
	EmpLogFile = ""

	// EmpConfigTar emp3r0r_operator_config.tar.xz
	EmpConfigTar = ""

	// emp3r0r-cat
	CAT = ""
)

const (
	// Temp where we save temp files
	Temp = "/tmp/emp3r0r/"

	// WWWRoot host static files for agent
	WWWRoot = Temp + "www/"

	// UtilsArchive host utils.tar.xz for agent
	UtilsArchive = WWWRoot + "utils.tar.xz"
)

func cleanupConfig() (err error) {
	dents, err := os.ReadDir(EmpWorkSpace)
	if err != nil {
		return
	}
	for _, d := range dents {
		if strings.HasSuffix(d.Name(), ".json") ||
			strings.HasSuffix(d.Name(), ".pem") ||
			strings.HasSuffix(d.Name(), ".history") {
			err = os.Remove(EmpWorkSpace + "/" + d.Name())
			if err != nil {
				return
			}
		}
	}
	return
}

func DownloadExtractConfig(url string, downloader func(string, string) error) (err error) {
	// Use a client-only destination to avoid clobbering the server's copy when running locally
	configTarPath := EmpConfigTar
	if !IsServer {
		configTarPath = filepath.Join(EmpWorkSpace, "emp3r0r_operator_config.client.tar.xz")
	}

	logging.Infof("Downloading and extracting config from %s to %s", url, configTarPath)
	// download config tarball from server, retry up to 10 times
	for i := range 10 {
		err = downloader(url, configTarPath)
		if err == nil {
			break
		}
		logging.Warningf("Failed to download config (attempt %d/10): %v", i+1, err)
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to download config after 10 attempts: %v", err)
	}

	// remove existing config files for a clean start
	err = cleanupConfig()
	if err != nil {
		return
	}
	// re-create workspace
	err = SetupFilePaths()
	if err != nil {
		return
	}

	// unarchive config files to workspace
	defer func() {
		if !IsServer && configTarPath != EmpConfigTar {
			_ = os.Remove(configTarPath)
		}
	}()
	return arc.Unarchive(configTarPath, HOME)
}

func SetupFilePaths() (err error) {
	HOME, err = os.UserHomeDir()
	if err != nil {
		return
	}
	EmpConfigTar = HOME + "/emp3r0r_operator_config.tar.xz"
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

	// cd to workspace
	err = os.Chdir(EmpWorkSpace)
	if err != nil {
		return fmt.Errorf("cd to workspace %s: %v", EmpWorkSpace, err)
	}

	// Module directories
	ModuleDirs = []string{EmpDataDir + "/modules", EmpWorkSpace + "/modules"}

	return nil
}

// CopyStubs copy agent stubs to ~/.emp3r0r, must be run after SetupFilePaths
func CopyStubs() (err error) {
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
	return nil
}
