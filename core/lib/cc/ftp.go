package cc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// StatFile Get stat info of a file on agent
func StatFile(filepath string, a *agent.SystemInfo) (fi *util.FileStat, err error) {
	cmd := fmt.Sprintf("!stat %s %s", filepath, uuid.NewString())
	err = SendCmd(cmd, a)
	if err != nil {
		return
	}
	var fileinfo util.FileStat

	defer func() {
		CmdResultsMutex.Lock()
		delete(CmdResults, cmd)
		CmdResultsMutex.Unlock()
	}()

	for {
		time.Sleep(100 * time.Millisecond)
		res, exists := CmdResults[cmd]
		if exists {
			err = json.Unmarshal([]byte(res), &fileinfo)
			if err != nil {
				return
			}
			fi = &fileinfo
			break
		}
	}

	return
}

// PutFile put file to agent
func PutFile(lpath, rpath string, a *agent.SystemInfo) error {
	// open and read the target file
	f, err := os.Open(lpath)
	if err != nil {
		CliPrintError("PutFile: %v", err)
		return err
	}
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		CliPrintError("PutFile: %v", err)
		return err
	}

	// file sha256sum
	sum := sha256.Sum256(bytes)

	// file size
	size := len(bytes)
	sizemB := float32(size) / 1024 / 1024
	CliPrintInfo("\nPutFile:\nUploading '%s' to\n'%s' "+
		"on %s, agent [%d]\n"+
		"size: %d bytes (%.2fMB)\n"+
		"sha256sum: %x",
		lpath, rpath,
		a.IP, Targets[a].Index,
		size, sizemB,
		sum,
	)

	// base64 encode
	payload := base64.StdEncoding.EncodeToString(bytes)

	fileData := agent.MsgTunData{
		Payload: "FILE" + agent.OpSep + rpath + agent.OpSep + payload,
		Tag:     a.Tag,
	}

	// send
	err = Send2Agent(&fileData, a)
	if err != nil {
		CliPrintError("PutFile: %v", err)
		return err
	}
	return nil
}

// GetFile get file from agent
func GetFile(filepath string, a *agent.SystemInfo) error {
	if !util.IsFileExist(FileGetDir) {
		err := os.MkdirAll(FileGetDir, 0700)
		if err != nil {
			return fmt.Errorf("GetFile mkdir %s: %v", FileGetDir, err)
		}
	}
	var data agent.MsgTunData
	filename := FileGetDir + util.FileBaseName(filepath) // will copy the downloaded file here when we are done
	tempname := filename + ".downloading"                // will be writing to this file

	// stat target file, know its size, and allocate the file on disk
	fi, err := StatFile(filepath, a)
	if err != nil {
		return fmt.Errorf("GetFile: failed to stat %s: %v", filepath, err)
	}
	fileinfo := *fi
	filesize := fileinfo.Size
	err = util.FileAllocate(filename, filesize)
	if err != nil {
		return fmt.Errorf("GetFile: %s allocate file: %v", filepath, err)
	}
	CliPrintInfo("We will be downloading %s, %d bytes in total (%s)", filepath, filesize, fileinfo.Checksum)

	// what if we have downloaded part of the file
	var offset int64 = 0
	if util.IsFileExist(tempname) {
		fiTotal, err := os.Stat(filename)
		if err != nil {
			CliPrintWarning("GetFile: read %s: %v", filename, err)
		}
		fiHave, err := os.Stat(tempname)
		if err != nil {
			CliPrintWarning("GetFile: read %s: %v", tempname, err)
		}
		offset = fiTotal.Size() - fiHave.Size()
	}

	// mark this file transfer stream
	ftpSh := &StreamHandler{}
	// tell agent where to seek the left bytes
	ftpSh.Token = uuid.NewString()
	ftpSh.Mutex = &sync.Mutex{}
	ftpSh.Buf = make(chan []byte)
	ftpSh.BufSize = 1024
	ftpSh.Mutex.Lock()
	FTPStreams[filepath] = ftpSh
	ftpSh.Mutex.Unlock()
	cmd := fmt.Sprintf("#get %s %d %s", filepath, offset, ftpSh.Token)
	// register FTP handler
	data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, cmd)
	data.Tag = a.Tag
	err = Send2Agent(&data, a)
	if err != nil {
		CliPrintError("GetFile send command: %v", err)
		return err
	}
	return nil
}
