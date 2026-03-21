package ftp

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archives"
	"github.com/schollz/progressbar/v3"
)

const maxTransferSizeBuffer int64 = 1024 * 1024

var errTransferSizeExceeded = errors.New("decompressed transfer exceeds expected size")

func copyWithDecompressedLimit(dst io.Writer, src io.Reader, expectedSize int64) (int64, error) {
	if expectedSize < 0 {
		return 0, errors.New("expected size cannot be negative")
	}
	if expectedSize > math.MaxInt64-maxTransferSizeBuffer-1 {
		return 0, errors.New("expected size too large")
	}

	limit := expectedSize + maxTransferSizeBuffer
	limitedReader := io.LimitReader(src, limit+1)

	n, err := io.Copy(dst, limitedReader)
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, errTransferSizeExceeded
	}

	return n, nil
}

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

// HandleFTPStream processes file transfer requests over a continuous stream.
func HandleFTPStream(conn io.ReadWriteCloser, token string, remoteAddr string, cancel context.CancelFunc) {
	logging.Debugf("FTP connection (%s) from %s", token, remoteAddr)
	tokenSplit := strings.Split(token, "-")
	if len(tokenSplit) != 2 {
		logging.Errorf("Invalid token: %s", token)
		conn.Close()
		cancel()
		return
	}
	mustHaveChecksum := tokenSplit[1]

	// Determine file paths and lookup StreamHandler.
	filename := ""
	var sh *network.StreamHandler
	network.FTPStreams.Range(func(fname, value any) bool {
		persh := value.(*network.StreamHandler)
		if token == persh.Token {
			filename = fname.(string)
			sh = persh
			return false // stop iteration
		}
		return true
	})
	if filename == "" || sh == nil {
		logging.Errorf("Failed to parse filename for token %s", token)
		conn.Close()
		cancel()
		return
	}

	// Check connection occupancy
	if sh.Secure != nil {
		logging.Errorf("handleFTPStream: connection occupied")
		conn.Close()
		cancel()
		return
	}
	sh.Secure = conn
	sh.Cancel = cancel

	mapKey := filename
	// Prepare file paths. targetFile is the final destination, filewrite is the temp file that we write to...
	writeDir, targetFile, filewrite, lock := GenerateGetFilePaths(filename)
	logging.Debugf("Downloading to %s, saving to %s, using lock file %s", filewrite, targetFile, lock)
	if !util.IsDirExist(writeDir) {
		logging.Debugf("Creating directory: %s", writeDir)
		err := os.MkdirAll(writeDir, 0o700)
		if err != nil {
			logging.Errorf("Mkdir %s: %v", writeDir, err)
			return
		}
	}
	if util.IsExist(lock) {
		logging.Errorf("%s is already being downloaded", filename)
		sh.Close()
		sh.Cancel()
		return
	}
	_, err := os.Create(lock)
	if err != nil {
		logging.Errorf("Create lock file error: %v", err)
		sh.Close()
		sh.Cancel()
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
		if sh != nil {
			err = sh.Close()
			if err != nil {
				logging.Errorf("Failed to close connection: %v", err)
			}
			if sh.Cancel != nil {
				sh.Cancel()
			}
		}
		network.FTPStreams.Delete(mapKey)
		logging.Warningf("Closed FTP connection from %s", remoteAddr)
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
	decompressor, err := archives.Zstd{}.OpenReader(sh)
	if err != nil {
		logging.Errorf("Open decompressor error: %v", err)
		return
	}
	defer decompressor.Close()
	n, err := copyWithDecompressedLimit(f, decompressor, targetSize)
	if err != nil {
		if errors.Is(err, errTransferSizeExceeded) {
			logging.Errorf("Security Alert: transfer for %s exceeded expected size (%d bytes + %d bytes buffer); received %d bytes",
				targetFile, targetSize, maxTransferSizeBuffer, n)
			return
		}
		logging.Warningf("Saving file failed after %d bytes: %v", n, err)
		return
	}
}
