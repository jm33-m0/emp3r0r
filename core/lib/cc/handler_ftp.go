package cc

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archives"
	"github.com/posener/h2conn"
	"github.com/schollz/progressbar/v3"
)

// progressMonitor updates the progress bar.
func progressMonitor(bar *progressbar.ProgressBar, filewrite, targetFile string, targetSize int64) {
	if targetSize == 0 {
		LogWarning("progressMonitor: targetSize is 0")
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
		LogInfo("%s: %.2f%% (%d of %d bytes) at %.2fKB/s, %ds passed, %ds left",
			strconv.Quote(targetFile),
			state.CurrentPercent*100, nowSize, targetSize,
			state.KBsPerSecond, int(state.SecondsSince), int(state.SecondsLeft))
		if nowSize >= targetSize || state.CurrentPercent >= 1 {
			break
		}
		time.Sleep(5 * time.Second)
	}
}

// handleFTPTransfer processes file transfer requests.
func handleFTPTransfer(wrt http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token := vars["token"]

	// Check connection occupancy and accept connection via H2Conn.
	// ...existing connection setup code...
	var sh *StreamHandler = FTPStreams[token] // assume FTPStreams token mapping exists
	if sh.H2x != nil && (sh.H2x.Ctx != nil || sh.H2x.Cancel != nil || sh.H2x.Conn != nil) {
		LogError("handleFTPTransfer: connection occupied")
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var err error
	sh.H2x = &emp3r0r_def.H2Conn{}
	sh.H2x.Conn, err = h2conn.Accept(wrt, req)
	if err != nil {
		LogError("handleFTPTransfer: failed connection from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	sh.H2x.Ctx, sh.H2x.Cancel = context.WithCancel(req.Context())
	defer sh.H2x.Conn.Close()
	defer sh.H2x.Cancel()

	// Verify token consistency & extract checksum.
	if token != sh.Token {
		LogError("Invalid ftp token '%s vs %s'", token, sh.Token)
		return
	}
	LogDebug("FTP connection (%s) from %s", sh.Token, req.RemoteAddr)
	tokenSplit := strings.Split(token, "-")
	if len(tokenSplit) != 2 {
		LogError("Invalid token: %s", token)
		return
	}
	mustHaveChecksum := tokenSplit[1]

	// Determine file paths.
	filename := ""
	for fname, persh := range FTPStreams {
		if sh.Token == persh.Token {
			filename = fname
			break
		}
	}
	if filename == "" {
		LogError("Failed to parse filename for token %s", sh.Token)
		return
	}
	mapKey := filename
	writeDir, targetFile, filewrite, lock := generateGetFilePaths(filename)
	filename = filepath.Clean(filename)
	filename = util.FileBaseName(filename)
	LogDebug("Downloading to %s, saving to %s, using lock file %s", filewrite, targetFile, lock)
	if !util.IsDirExist(writeDir) {
		LogDebug("Creating directory: %s", writeDir)
		err = os.MkdirAll(writeDir, 0o700)
		if err != nil {
			LogError("Mkdir %s: %v", writeDir, err)
			return
		}
	}
	if util.IsExist(lock) {
		LogError("%s is already being downloaded", filename)
		http.Error(wrt, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	_, err = os.Create(lock)
	if err != nil {
		LogError("Create lock file error: %v", err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !util.IsExist(FileGetDir) {
		err = os.MkdirAll(FileGetDir, 0o700)
		if err != nil {
			LogError("Mkdir FileGetDir %s: %v", FileGetDir, err)
			return
		}
	}

	// Open file for writing.
	var targetSize, nowSize int64
	f, err := os.OpenFile(filewrite, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		LogError("Open file error: %v", err)
		return
	}
	defer f.Close()
	LogDebug("Writing to file %s", filewrite)

	// Initialize progress bar.
	targetSize = util.FileSize(targetFile)
	nowSize = util.FileSize(filewrite)
	bar := progressbar.DefaultBytesSilent(targetSize)
	bar.Add64(nowSize)
	defer bar.Close()
	LogDebug("Initial sizes: target %d, current %d", targetSize, nowSize)
	go progressMonitor(bar, filewrite, targetFile, targetSize)

	// On-exit cleanup.
	cleanup := func() {
		if sh.H2x.Conn != nil {
			err = sh.H2x.Conn.Close()
			if err != nil {
				LogError("Failed to close connection: %v", err)
			}
		}
		sh.H2x.Cancel()
		FTPMutex.Lock()
		delete(FTPStreams, mapKey)
		FTPMutex.Unlock()
		LogWarning("Closed FTP connection from %s", req.RemoteAddr)
		err = os.Remove(lock)
		if err != nil {
			LogWarning("Remove lock %s: %v", lock, err)
		}
		nowSize = util.FileSize(filewrite)
		targetSize = util.FileSize(targetFile)
		if nowSize == targetSize && nowSize >= 0 {
			err = os.Rename(filewrite, targetFile)
			if err != nil {
				LogError("Rename file error %s: %v", targetFile, err)
			}
			checksum := tun.SHA256SumFile(targetFile)
			if checksum == mustHaveChecksum {
				LogSuccess("Downloaded %d bytes to %s (%s)", nowSize, targetFile, checksum)
				return
			}
			LogError("%s downloaded but checksum mismatch: %s vs %s", targetFile, checksum, mustHaveChecksum)
			return
		}
		if nowSize > targetSize {
			LogError("%s: downloaded (%d of %d bytes), error", targetFile, nowSize, targetSize)
			return
		}
		LogWarning("Incomplete download: %.4f%% (%d of %d bytes)", float64(nowSize)*100/float64(targetSize), nowSize, targetSize)
	}
	defer cleanup()

	// Decompress and write file data.
	decompressor, err := archives.Zstd{}.OpenReader(sh.H2x.Conn)
	if err != nil {
		LogError("Open decompressor error: %v", err)
		return
	}
	defer decompressor.Close()
	n, err := io.Copy(f, decompressor)
	if err != nil {
		LogWarning("Saving file failed after %d bytes: %v", n, err)
		return
	}
}
