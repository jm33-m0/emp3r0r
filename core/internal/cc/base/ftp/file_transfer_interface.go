package ftp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// UploadToAgent uploads a file to an agent.
// This is a convenience wrapper around PutFile that can be called from operator.
func UploadToAgent(src, dst string, target *def.Emp3r0rAgent) error {
	if target == nil {
		return fmt.Errorf("no target agent selected")
	}
	if src == "" || dst == "" {
		return fmt.Errorf("source and destination paths are required")
	}

	return PutFile(src, dst, target)
}

// DownloadFromAgent is the legacy download path for agents that cannot run the
// get_file BOF (Windows agents, and Linux agents whose binary is not x86-64).
// It drives the agent's built-in `get` command; Linux x86-64 agents use the
// module-backed path in the modules package instead.
func DownloadFromAgent(target *def.Emp3r0rAgent, filePath string, isRecursive bool, filter string) error {
	if target == nil {
		return fmt.Errorf("no target agent selected")
	}
	if filePath == "" {
		return fmt.Errorf("file path is required")
	}

	if isRecursive {
		cmdStr := fmt.Sprintf("get --file_path %s --filter %s --offset 0 --token %s",
			strconv.Quote(filePath), strconv.Quote(filter), strconv.Quote(uuid.NewString()))

		// A directory is never uploaded: the agent prints the matching paths as
		// the command result.
		logging.Infof("Waiting for response from agent %s", target.Tag)
		jobID := uuid.NewString()
		res, err := live.AwaitCmdResult(jobID, live.AgentReplyTimeout(), func() error {
			return sendCommand(cmdStr, jobID, target.Tag)
		})
		if err != nil {
			return fmt.Errorf("cannot get file list: %w", err)
		}
		logging.Infof("Got file list from %s", target.Tag)
		if res == "" {
			return fmt.Errorf("empty file list in directory: %s", filePath)
		}
		result := util.SanitizeText(res)
		logging.Debugf("Got file list: %s", result)

		files := strings.Split(result, "\n")

		logging.Infof("Downloading %d files", len(files))
		for n, file := range files {
			ftpSh, err := getFile(file, target)
			if err != nil {
				logging.Warningf("Cannot get %s: %v", file, err)
				continue
			}

			logging.Infof("Downloading %d/%d: %s", n+1, len(files), file)

			// A nil stream means the local copy was already complete.
			for ftpSh != nil {
				if val, ok := network.FTPStreams.Load(file); ok {
					if sh, ok := val.(*network.StreamHandler); ok && sh != nil && ftpSh.Token == sh.Token {
						util.TakeABlink()
						continue
					}
				}
				break
			}
		}

		var failedFiles []string
		logging.Infof("Checking %d downloads...", len(files))
		for _, file := range files {
			_, targetFile, tempname, lock := GenerateGetFilePaths(file)
			if util.IsFileExist(tempname) || util.IsFileExist(lock) || !util.IsFileExist(targetFile) {
				logging.Warningf("%s: download seems unsuccessful", file)
				failedFiles = append(failedFiles, file)
			}
		}
		if len(failedFiles) > 0 {
			logging.Errorf("Failed to download %d files: %s", len(failedFiles), strings.Join(failedFiles, ", "))
			return fmt.Errorf("failed to download %d files", len(failedFiles))
		}
		logging.Successf("All %d files downloaded successfully", len(files))
		return nil
	}

	ftpSh, err := getFile(filePath, target)
	if err != nil {
		return err
	}
	for ftpSh != nil {
		if val, ok := network.FTPStreams.Load(filePath); ok {
			if sh, ok := val.(*network.StreamHandler); ok && sh != nil && ftpSh.Token == sh.Token {
				util.TakeABlink()
				continue
			}
		}
		break
	}
	return nil
}
