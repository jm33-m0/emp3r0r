package operator

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func handleWWWRelayMessage(data *def.MsgTunData) bool {
	if data == nil {
		return false
	}
	if !strings.HasPrefix(data.Tag, def.TagWWWRelayRequestPrefix) {
		return false
	}

	streamID := strings.TrimPrefix(data.Tag, def.TagWWWRelayRequestPrefix)
	go serveWWWRelay(streamID)
	return true
}

func serveWWWRelay(streamID string) {
	localized, err := util.SecureLocalPath(streamID)
	if err != nil {
		_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(err.Error())})
		return
	}
	name := filepath.Base(localized)
	path := filepath.Join(live.WWWRoot, name)
	f, err := os.Open(path)
	if err != nil {
		_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(err.Error())})
		return
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if err := client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayDataPrefix + streamID, Response: chunk}); err != nil {
				logging.Errorf("WWW relay send failed for %q: %v", streamID, err)
				return
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayDonePrefix + streamID})
			} else {
				_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(readErr.Error())})
			}
			return
		}
	}
}
