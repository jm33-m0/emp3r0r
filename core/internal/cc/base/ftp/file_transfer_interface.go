package ftp

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// UploadToAgent uploads a file to an agent.
// This is a convenience wrapper around PutFile that can be called from operator.
func UploadToAgent(src, dst string, target *def.Emp3r0rAgent, saveToMem bool) error {
	if target == nil {
		return fmt.Errorf("no target agent selected")
	}
	if src == "" || dst == "" {
		return fmt.Errorf("source and destination paths are required")
	}

	return PutFile(src, dst, target, saveToMem)
}

// DownloadFromAgent downloads a file or directory from an agent.
// If isRecursive is true, downloads all files matching the filter regex.
// Returns error if download fails.
func DownloadFromAgent(target *def.Emp3r0rAgent, filePath string, isRecursive bool, filter string) error {
	if target == nil {
		return fmt.Errorf("no target agent selected")
	}
	if filePath == "" {
		return fmt.Errorf("file path is required")
	}

	if isRecursive {
		job_id := uuid.NewString()
		cmd_str := fmt.Sprintf("get --file_path %s --filter %s --offset 0 --token %s", filePath, strconv.Quote(filter), uuid.NewString())
		err := ExecCmd(cmd_str, job_id, target.Tag)
		if err != nil {
			return fmt.Errorf("cannot get file list: %v", err)
		}

		logging.Infof("Waiting for response from agent %s", target.Tag)
		var result string
		for i := 0; i < 10; i++ {
			res, ok := live.CmdResults.Load(job_id)
			if ok {
				result = res.(string)
				logging.Infof("Got file list from %s", target.Tag)
				live.CmdResults.Delete(job_id)
				if result == "" {
					return fmt.Errorf("empty file list in directory: %s", filePath)
				}
				break
			}
			time.Sleep(1 * time.Second)
		}
		result = util.SanitizeText(result)
		logging.Debugf("Got file list: %s", result)

		// download files
		files := strings.Split(result, "\n")
		failed_files := []string{}
		defer func() {
			logging.Infof("Checking %d downloads...", len(files))
			// check if downloads are successful
			for _, file := range files {
				// filenames
				_, target_file, tempname, lock := GenerateGetFilePaths(file)
				// check if download is successful
				if util.IsFileExist(tempname) || util.IsFileExist(lock) || !util.IsFileExist(target_file) {
					logging.Warningf("%s: download seems unsuccessful", file)
					failed_files = append(failed_files, file)
				}
			}
			if len(failed_files) > 0 {
				logging.Errorf("Failed to download %d files: %s", len(failed_files), strings.Join(failed_files, ", "))
			} else {
				logging.Successf("All %d files downloaded successfully", len(files))
			}
		}()

		logging.Infof("Downloading %d files", len(files))
		for n, file := range files {
			ftpSh, err := GetFile(file, target)
			if err != nil {
				logging.Warningf("Cannot get %s: %v", file, err)
				continue
			}

			logging.Infof("Downloading %d/%d: %s", n+1, len(files), file)

			// wait for file to be downloaded
			for {
				if val, ok := network.FTPStreams.Load(file); ok {
					sh := val.(*network.StreamHandler)
					if ftpSh.Token == sh.Token {
						util.TakeABlink()
						continue
					}
				}
				break
			}
		}

		if len(failed_files) > 0 {
			return fmt.Errorf("failed to download %d files", len(failed_files))
		}
		return nil
	} else {
		_, err := GetFile(filePath, target)
		return err
	}
}
