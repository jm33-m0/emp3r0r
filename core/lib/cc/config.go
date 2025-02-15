//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var RuntimeConfig = &emp3r0r_def.Config{}

// InitFilePaths set workspace, module directories, etc
func InitFilePaths() (err error) {
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
		LogWarning("Agent stubs: %v", err)
	}
	for _, stubFile := range stubFiles {
		copyErr := util.Copy(stubFile, EmpWorkSpace)
		if copyErr != nil {
			LogWarning("Agent stubs: %v", copyErr)
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
		Logger.Fatal("init_magic_str: %v", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name(), "stub-") {
			err = util.ReplaceBytesInFile(fmt.Sprintf("%s/%s", EmpWorkSpace, f.Name()),
				default_magic_str, emp3r0r_def.OneTimeMagicBytes)
			if err != nil {
				Logger.Error("init_magic_str %v", err)
			}
		}
	}
}
