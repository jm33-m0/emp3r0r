package ftp

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestCopyWithDecompressedLimit_AllowsExpectedSize(t *testing.T) {
	expectedSize := int64(32)
	data := bytes.Repeat([]byte("A"), int(expectedSize))

	var dst bytes.Buffer
	n, err := copyWithDecompressedLimit(&dst, bytes.NewReader(data), expectedSize)
	if err != nil {
		t.Fatalf("copyWithDecompressedLimit returned error: %v", err)
	}
	if n != expectedSize {
		t.Fatalf("copied bytes mismatch: got %d, want %d", n, expectedSize)
	}
	if !bytes.Equal(dst.Bytes(), data) {
		t.Fatalf("destination data mismatch")
	}
}

func TestCopyWithDecompressedLimit_BlocksOversizedStream(t *testing.T) {
	expectedSize := int64(64)
	overLimit := expectedSize + maxTransferSizeBuffer + 2
	data := bytes.Repeat([]byte("B"), int(overLimit))

	var dst bytes.Buffer
	n, err := copyWithDecompressedLimit(&dst, bytes.NewReader(data), expectedSize)
	if !errors.Is(err, errTransferSizeExceeded) {
		t.Fatalf("expected errTransferSizeExceeded, got %v", err)
	}
	if n != expectedSize+maxTransferSizeBuffer+1 {
		t.Fatalf("copied bytes mismatch when limited: got %d, want %d", n, expectedSize+maxTransferSizeBuffer+1)
	}
}

func TestCopyWithDecompressedLimit_RejectsNegativeExpectedSize(t *testing.T) {
	var dst bytes.Buffer
	_, err := copyWithDecompressedLimit(&dst, bytes.NewReader([]byte("x")), -1)
	if err == nil {
		t.Fatal("expected error for negative expected size")
	}
}

// TestHandleFTPTransfer_PathValidation tests that path generation works correctly for various path types
func TestHandleFTPTransfer_PathValidation(t *testing.T) {
	// Setup test environment
	tmpDir := t.TempDir()
	live.FileGetDir = filepath.Join(tmpDir, "downloads")

	testCases := []struct {
		name         string
		remotePath   string
		expectedPath string // expected local path structure (relative to FileGetDir)
	}{
		{
			name:         "Absolute path - Linux home directory",
			remotePath:   "/home/kali/zsh/completion.zsh",
			expectedPath: "home/kali/zsh/completion.zsh",
		},
		{
			name:         "Absolute path - /etc/passwd",
			remotePath:   "/etc/passwd",
			expectedPath: "etc/passwd",
		},
		{
			name:         "Relative path",
			remotePath:   "relative/file.txt",
			expectedPath: "relative/file.txt",
		},
		{
			name:         "Path traversal attempt",
			remotePath:   "../../../../etc/passwd",
			expectedPath: "passwd", // Should be flattened to basename
		},
		{
			name:         "Deep nested path",
			remotePath:   "/var/log/app/2024/01/20/debug.log",
			expectedPath: "var/log/app/2024/01/20/debug.log",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate paths
			writeDir, targetFile, tempFile, lockFile := GenerateGetFilePaths(tc.remotePath)

			// Check that all paths are within FileGetDir
			if !strings.HasPrefix(writeDir, live.FileGetDir) {
				t.Errorf("writeDir %s is not within FileGetDir %s", writeDir, live.FileGetDir)
			}
			if !strings.HasPrefix(targetFile, live.FileGetDir) {
				t.Errorf("targetFile %s is not within FileGetDir %s", targetFile, live.FileGetDir)
			}
			if !strings.HasPrefix(tempFile, live.FileGetDir) {
				t.Errorf("tempFile %s is not within FileGetDir %s", tempFile, live.FileGetDir)
			}
			if !strings.HasPrefix(lockFile, live.FileGetDir) {
				t.Errorf("lockFile %s is not within FileGetDir %s", lockFile, live.FileGetDir)
			}

			// Check expected path structure
			expectedFullPath := filepath.Join(live.FileGetDir, tc.expectedPath)
			if targetFile != expectedFullPath {
				t.Errorf("targetFile path incorrect: got %s, want %s", targetFile, expectedFullPath)
			}

			// Verify no path traversal
			if strings.Contains(targetFile, "..") {
				t.Errorf("targetFile contains traversal: %s", targetFile)
			}

			t.Logf("✓ Remote: %s -> Local: %s", tc.remotePath, targetFile)
		})
	}
}

// TestHandleFTPTransfer_AbsolutePathRegression specifically tests the bug fix for absolute paths
func TestHandleFTPTransfer_AbsolutePathRegression(t *testing.T) {
	// This test ensures that absolute remote paths like "/home/kali/zsh/completion.zsh"
	// are correctly handled and don't trigger "invalid path" errors

	tmpDir := t.TempDir()
	live.FileGetDir = filepath.Join(tmpDir, "downloads")

	// The exact path from the bug report
	remotePath := "/home/kali/zsh/completion.zsh"
	testContent := []byte("# zsh completion script")
	_ = crypto.SHA256Sum(string(testContent))

	// Verify that GenerateGetFilePaths handles this correctly
	writeDir, targetFile, tempFile, lockFile := GenerateGetFilePaths(remotePath)

	// Check that paths are within FileGetDir
	if !strings.HasPrefix(writeDir, live.FileGetDir) {
		t.Errorf("writeDir %s is not within FileGetDir %s", writeDir, live.FileGetDir)
	}
	if !strings.HasPrefix(targetFile, live.FileGetDir) {
		t.Errorf("targetFile %s is not within FileGetDir %s", targetFile, live.FileGetDir)
	}
	if !strings.HasPrefix(tempFile, live.FileGetDir) {
		t.Errorf("tempFile %s is not within FileGetDir %s", tempFile, live.FileGetDir)
	}
	if !strings.HasPrefix(lockFile, live.FileGetDir) {
		t.Errorf("lockFile %s is not within FileGetDir %s", lockFile, live.FileGetDir)
	}

	// Verify the structure is preserved (without leading /)
	expectedPath := filepath.Join(live.FileGetDir, "home/kali/zsh/completion.zsh")
	if targetFile != expectedPath {
		t.Errorf("targetFile path incorrect: got %s, want %s", targetFile, expectedPath)
	}

	// Verify that the path doesn't contain ".." or other traversal attempts
	if strings.Contains(targetFile, "..") {
		t.Errorf("targetFile contains traversal: %s", targetFile)
	}

	t.Logf("✓ Absolute path correctly handled:")
	t.Logf("  Remote: %s", remotePath)
	t.Logf("  Local:  %s", targetFile)
	t.Logf("  Temp:   %s", tempFile)
	t.Logf("  Lock:   %s", lockFile)
}

// TestHandleFTPTransfer_TraversalPrevention tests that path traversal is prevented
func TestHandleFTPTransfer_TraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	live.FileGetDir = filepath.Join(tmpDir, "downloads")

	maliciousPaths := []string{
		"../../../../etc/passwd",
		"../../../etc/shadow",
		"../../.ssh/id_rsa",
		"./../../secrets.txt",
		"..",
		"../..",
		".",
		"/",
		"",
		"\\",
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			writeDir, targetFile, _, _ := GenerateGetFilePaths(malPath)

			// Verify paths are contained within FileGetDir
			if !strings.HasPrefix(writeDir, live.FileGetDir) {
				t.Errorf("Path traversal detected in writeDir: %s escapes %s", writeDir, live.FileGetDir)
			}
			if !strings.HasPrefix(targetFile, live.FileGetDir+string(filepath.Separator)) {
				t.Errorf("Path traversal or directory clobber detected in targetFile: %s is not strictly inside %s", targetFile, live.FileGetDir)
			}

			// Verify no ".." in final path
			if strings.Contains(targetFile, "..") {
				t.Errorf("Path still contains '..': %s", targetFile)
			}

			t.Logf("✓ Malicious path safely handled: %s -> %s", malPath, targetFile)
		})
	}
}

func TestFileAllocate_BoundsAndDirGuard(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "alloc.bin")

	if err := util.FileAllocate(target, -1); err == nil {
		t.Fatal("expected error for negative FileAllocate size")
	}
	if err := util.FileAllocate(target, util.MaxFileAllocateBytes+1); err == nil {
		t.Fatal("expected error for oversized FileAllocate size")
	}
	if err := util.FileAllocate(tmpDir, 64); err == nil {
		t.Fatal("expected error when FileAllocate targets an existing directory")
	}
}

// streamConn feeds a fixed byte stream to the receiver; bytes.Reader reports a
// clean io.EOF once the stream is exhausted, which is what the agent's
// connection does at the end of an upload.
type streamConn struct {
	r *bytes.Reader
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *streamConn) Close() error                { return nil }

// gzipStream compresses payload the way the agent does, one gzip member for the
// whole body.
func gzipStream(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// receiveOneTransfer registers an FTP stream for remotePath, feeds it `stream`
// through the real receiver, and returns once the receiver has unregistered the
// stream, which is the signal an operator waits for.
func receiveOneTransfer(t *testing.T, remotePath string, stream []byte, payloadSize int, checksum string) {
	t.Helper()
	token := util.RandHexString() + "-" + checksum
	sh := &network.StreamHandler{
		Token:           token,
		OperatorSession: "test-operator",
		ExpectedSize:    int64(payloadSize),
		Checksum:        checksum,
	}
	network.FTPStreams.Store(remotePath, sh)
	network.FTPStreams.Store("token:"+token, sh)
	t.Cleanup(func() {
		network.FTPStreams.Delete(remotePath)
		network.FTPStreams.Delete("token:" + token)
	})

	go HandleFTPStream(&streamConn{r: bytes.NewReader(stream)}, token, "test", func() {})

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := network.FTPStreams.Load(remotePath); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("receiver never unregistered %s", remotePath)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// prepareDownloadDir points the receiver at a private download directory for
// one test and reports the destination paths for remotePath.
func prepareDownloadDir(t *testing.T, remotePath string) (saveToFile, tempname, lock string) {
	t.Helper()
	live.FileGetDir = t.TempDir()
	writeDir, saveToFile, tempname, lock := GenerateGetFilePaths(remotePath)
	if err := os.MkdirAll(writeDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", writeDir, err)
	}
	return saveToFile, tempname, lock
}

// TestHandleFTPStreamFinalizesBeforeUnregistering pins the operator-visible
// contract: a vanished stream registration means the destination is final, so a
// caller that checks the destination right after the transfer ends never sees
// the temp file of a transfer that is still being renamed.
func TestHandleFTPStreamFinalizesBeforeUnregistering(t *testing.T) {
	payload := bytes.Repeat([]byte("transfer-finalize-"), 8192)
	compressed := gzipStream(t, payload)
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	const remotePath = "/var/log/finalize.log"
	saveToFile, tempname, lock := prepareDownloadDir(t, remotePath)

	receiveOneTransfer(t, remotePath, compressed, len(payload), digest)

	got, err := os.ReadFile(saveToFile)
	if err != nil {
		t.Fatalf("read %s: %v", saveToFile, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("%s: got %d bytes, want %d", saveToFile, len(got), len(payload))
	}
	if util.IsFileExist(tempname) {
		t.Fatalf("temp file survived a completed transfer: %s", tempname)
	}
	if util.IsFileExist(lock) {
		t.Fatalf("lock file survived a completed transfer: %s", lock)
	}
}

// TestHandleFTPStreamMarksIncompleteTransfer keeps the other side of the
// contract: a transfer that ends early keeps its temp file, so the caller can
// tell it apart from a finished one instead of trusting a size-verified file
// that is not complete. The lock only marks an in-progress transfer and is
// always removed.
func TestHandleFTPStreamMarksIncompleteTransfer(t *testing.T) {
	payload := bytes.Repeat([]byte("truncated-body-"), 16384)
	compressed := gzipStream(t, payload)
	truncated := compressed[:len(compressed)/2]
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	const remotePath = "/var/log/truncated.log"
	saveToFile, tempname, lock := prepareDownloadDir(t, remotePath)

	receiveOneTransfer(t, remotePath, truncated, len(payload), digest)

	if !util.IsFileExist(tempname) {
		t.Fatalf("truncated transfer did not leave its temp file: %s", tempname)
	}
	if util.IsFileExist(lock) {
		t.Fatalf("truncated transfer left its lock file behind: %s", lock)
	}
	if util.IsFileExist(saveToFile) {
		t.Fatalf("truncated transfer produced a final file: %s", saveToFile)
	}
}

// TestHandleFTPStreamRejectsChecksumMismatch pins that the digest is verified
// before the temp file is published. A same-size transfer with a different
// digest must not appear at the destination: the operator keeps whatever is
// there, and the transfer is reported as failed.
func TestHandleFTPStreamRejectsChecksumMismatch(t *testing.T) {
	payload := bytes.Repeat([]byte("tampered-body-"), 8192)
	compressed := gzipStream(t, payload)
	wrongDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("something else")))
	const remotePath = "/var/log/tampered.log"
	saveToFile, tempname, lock := prepareDownloadDir(t, remotePath)

	receiveOneTransfer(t, remotePath, compressed, len(payload), wrongDigest)

	if util.IsFileExist(saveToFile) {
		t.Fatalf("checksum mismatch was published to %s", saveToFile)
	}
	if !util.IsFileExist(tempname) {
		t.Fatalf("checksum mismatch discarded the received bytes: %s", tempname)
	}
	if got := util.FileSize(tempname); got != int64(len(payload)) {
		t.Fatalf("%s: kept %d bytes, want %d", tempname, got, len(payload))
	}
	if util.IsFileExist(lock) {
		t.Fatalf("checksum mismatch left the lock behind: %s", lock)
	}
}
