package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/def"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/util"
	"github.com/spf13/cobra"
)

func CmdUploadToAgent(cmd *cobra.Command, args []string) {
	target := agents.MustGetActiveAgent()
	if target == nil {
		logging.Errorf("You have to select a target first")
		return
	}

	src, err := cmd.Flags().GetString("src")
	if err != nil {
		logging.Errorf("UploadToAgent: %v", err)
		return
	}
	dst, err := cmd.Flags().GetString("dst")
	if err != nil {
		logging.Errorf("UploadToAgent: %v", err)
		return
	}

	if src == "" || dst == "" {
		logging.Errorf(cmd.UsageString())
		return
	}

	if err := PutFile(src, dst, target); err != nil {
		logging.Errorf("Cannot put %s: %v", src, err)
	}
}

// let it run in the background
func CmdDownloadFromAgent(cmd *cobra.Command, args []string) {
	go downloadFromAgent(cmd, args)
}

func downloadFromAgent(cmd *cobra.Command, args []string) {
	target := agents.MustGetActiveAgent()
	if target == nil {
		logging.Errorf("You have to select a target first")
		return
	}
	// parse command-line arguments using pflag
	isRecursive, _ := cmd.Flags().GetBool("recursive")
	filter, _ := cmd.Flags().GetString("regex")

	file_path, err := cmd.Flags().GetString("path")
	if err != nil {
		logging.Errorf("download: %v", err)
		return
	}
	if file_path == "" {
		logging.Errorf("download: path is required")
		return
	}

	if isRecursive {
		cmd_id := uuid.NewString()
		err = agents.SendCmdToCurrentTarget(fmt.Sprintf("get --file_path %s --filter %s --offset 0 --token %s", file_path, strconv.Quote(filter), uuid.NewString()), cmd_id)
		if err != nil {
			logging.Errorf("Cannot get %v+: %v", args, err)
			return
		}
		logging.Infof("Waiting for response from agent %s", target.Tag)
		var result string
		var exists bool
		for i := 0; i < 10; i++ {
			result, exists = def.CmdResults[cmd_id]
			if exists {
				logging.Infof("Got file list from %s", target.Tag)
				def.CmdResultsMutex.Lock()
				delete(def.CmdResults, cmd_id)
				def.CmdResultsMutex.Unlock()
				if result == "" {
					logging.Errorf("Cannot get %s: empty file list in directory", file_path)
				}
				break
			}
			time.Sleep(1 * time.Second)
		}
		logging.Debugf("Got file list: %s", result)

		// download files
		files := strings.Split(result, "\n")
		failed_files := []string{}
		defer func() {
			logging.Printf("Checking %d downloads...", len(files))
			// check if downloads are successful
			for _, file := range files {
				// filenames
				_, target_file, tempname, lock := generateGetFilePaths(file)
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

			logging.Printf("Downloading %d/%d: %s", n+1, len(files), file)

			// wait for file to be downloaded
			for {
				if sh, ok := network.FTPStreams[file]; ok {
					if ftpSh.Token == sh.Token {
						util.TakeABlink()
						continue
					}
				}
				break
			}
		}
	} else {
		if _, err := GetFile(file_path, target); err != nil {
			logging.Errorf("Cannot get %s: %v", strconv.Quote(file_path), err)
		}
	}
}
