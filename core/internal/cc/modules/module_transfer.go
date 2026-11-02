package modules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// Names of the file-transfer modules. They are ordinary manifests whose
// transfer parameters are declared `internal`: the C2 owns those values.
const ModGetFile = "get_file"

// The provider is a variable so tests can substitute it.
var prepareGetFileStream = ftp.PrepareGetFileStream

// prepareModuleParameters fills the parameters that only the C2 can supply for
// operator-driven file transfer, before the invocation is packed. Their
// manifest entries are `internal`, so the console never asks the operator for
// them.
//
// get_file needs the token and the resume offset of the FTP stream that receives
// the agent's upload.
//
// done reports that the request is already satisfied, so no command has to be
// sent.
func prepareModuleParameters(config *def.ModuleConfig, target *def.Emp3r0rAgent, flags map[string]string) (done bool, err error) {
	if config == nil || flags == nil {
		return false, nil
	}

	switch strings.ToLower(config.Name) {
	case ModGetFile:
		path := strings.TrimSpace(flags["path"])
		if path == "" {
			return false, fmt.Errorf("option path is required")
		}
		// A caller that already prepared the stream (the operator `get`
		// command) owns the token and offset; do not register a second stream.
		if flags["stream"] != "" && flags["offset"] != "" {
			return false, nil
		}
		if target == nil {
			return false, fmt.Errorf("no target agent")
		}
		transfer, err := prepareGetFileStream(path, target)
		if err != nil {
			return false, err
		}
		if transfer.Complete {
			logging.Successf("%s is already downloaded", path)
			return true, nil
		}
		flags["stream"] = transfer.Token
		flags["offset"] = strconv.FormatInt(transfer.Offset, 10)
	}

	return false, nil
}
