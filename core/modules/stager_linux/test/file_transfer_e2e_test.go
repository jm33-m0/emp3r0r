//go:build linux && cgo

package shellcode_stager

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// e2eTransferSize is deliberately larger than the 64 MiB scratch buffer the
// transfer code used to cap a body at, so a buffered implementation cannot pass.
const e2eTransferSize = 70 << 20

// e2eTransferSizes walks the size boundary of the operator -> agent path so a
// failure names the layer that truncates instead of only "no bytes".
var e2eTransferSizes = []int{32 << 10, 64 << 10, 256 << 10, 1 << 20, 8 << 20, e2eTransferSize}

// transferSizes returns the sweep, or the single size named in
// EMP3R0R_E2E_SIZE (bytes) so one boundary can be exercised on its own.
func transferSizes() []int {
	if v := os.Getenv("EMP3R0R_E2E_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return []int{n}
		}
	}
	return e2eTransferSizes
}

// testFTPRelayConn feeds the agent's FTP upload into ftp.HandleFTPStream, the
// same way operator/ftp_relay.go does for the console.
type testFTPRelayConn struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
	buf    []byte
}

func newTestFTPRelayConn() *testFTPRelayConn {
	return &testFTPRelayConn{ch: make(chan []byte, 64), closed: make(chan struct{})}
}

func (c *testFTPRelayConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		select {
		case chunk := <-c.ch:
			c.buf = chunk
		case <-c.closed:
			// A queued frame still belongs to the stream; reporting EOF first
			// truncates the last gzip member.
			select {
			case chunk := <-c.ch:
				c.buf = chunk
				continue
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *testFTPRelayConn) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("ftp relay is read-only")
}

func (c *testFTPRelayConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// Push never closes the queue, so a relay frame that arrives after Done (or
// after the test ends) cannot panic with "send on closed channel".
func (c *testFTPRelayConn) Push(data []byte) error {
	chunk := append([]byte(nil), data...)
	select {
	case <-c.closed:
		return io.EOF
	default:
	}
	select {
	case c.ch <- chunk:
		return nil
	case <-c.closed:
		return io.EOF
	}
}

var testFTPRelayConns sync.Map // token -> *testFTPRelayConn

// testFTPRelayMessage relays FTP-route bytes to ftp.HandleFTPStream. This is the
// operator half of an agent upload, exercised with the real receiver.
func testFTPRelayMessage(tag string, data []byte) bool {
	switch {
	case strings.HasPrefix(tag, def.TagFTPRelayDataPrefix):
		token := strings.TrimPrefix(tag, def.TagFTPRelayDataPrefix)
		conn := getTestFTPRelayConn(token)
		if conn == nil {
			return true
		}
		_ = conn.Push(data)
		return true
	case strings.HasPrefix(tag, def.TagFTPRelayDonePrefix):
		token := strings.TrimPrefix(tag, def.TagFTPRelayDonePrefix)
		if val, ok := testFTPRelayConns.LoadAndDelete(token); ok {
			_ = val.(*testFTPRelayConn).Close()
		}
		return true
	case strings.HasPrefix(tag, def.TagFTPRelayErrorPrefix):
		token := strings.TrimPrefix(tag, def.TagFTPRelayErrorPrefix)
		if val, ok := testFTPRelayConns.LoadAndDelete(token); ok {
			_ = val.(*testFTPRelayConn).Close()
		}
		return true
	default:
		return false
	}
}

func getTestFTPRelayConn(token string) *testFTPRelayConn {
	if val, ok := testFTPRelayConns.Load(token); ok {
		return val.(*testFTPRelayConn)
	}
	// The stream handler is registered by ftp.PrepareGetFileStream before the
	// agent is told to upload; wait briefly for it like the console does.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := network.FTPStreams.Load("token:" + token); ok {
			break
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	conn := newTestFTPRelayConn()
	actual, loaded := testFTPRelayConns.LoadOrStore(token, conn)
	if loaded {
		return actual.(*testFTPRelayConn)
	}
	go ftp.HandleFTPStream(conn, token, "e2e-operator", func() {})
	return conn
}

// runFileTransferChecks drives the real operator command (`put`) and the
// get_file module against the running C agent and the real C2 relays: the
// download gate, then a size sweep up to a body above the old 64 MiB cap.
func runFileTransferChecks(t *testing.T, agent *def.Emp3r0rAgent, doneChan <-chan error, agentOut *bytes.Buffer) {
	t.Helper()

	coreDir, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve core dir: %v", err)
	}
	// Load the real manifests: the module dispatcher, the C2-owned parameters
	// and the BOF packing are all under test here.
	live.ModuleDirs = []string{filepath.Join(coreDir, "modules")}
	modules.InitModules()
	live.FileGetDir = t.TempDir() + "/"

	// The console injects these; the module dispatcher and the FTP client call
	// them directly.
	prevSender, prevFTPSender := modules.CmdSender, ftp.ExecCmd
	prevTarget := live.GetActiveAgent()
	modules.CmdSender = controllers.ExecuteCommand
	ftp.ExecCmd = controllers.ExecuteCommand
	t.Cleanup(func() {
		modules.CmdSender = prevSender
		ftp.ExecCmd = prevFTPSender
		live.SetActiveAgent(prevTarget)
	})

	// --- Operator-initiated downloads only: the agent cannot decide what to
	// fetch, and a registration is bound to one agent and used once. ---
	t.Run("download-refuses-unregistered", func(t *testing.T) {
		// The name exists in the operator's www root but was never registered.
		secret := "not-registered-" + fmt.Sprintf("%d.bin", time.Now().UnixNano())
		if err := os.WriteFile(filepath.Join(paths.WWWRoot, secret), []byte("secret"), 0o600); err != nil {
			t.Fatalf("write sentinel: %v", err)
		}
		got := runC2Command(t, agent, doneChan, agentOut, "download "+secret)
		if !strings.Contains(got, "download failed") {
			t.Fatalf("unregistered file was served to the agent: %q", got)
		}
		// The same name is only served once the operator registers it.
		if err := client.RegisterWWWDownload(secret, agent.UUID, 6, ""); err != nil {
			t.Fatalf("register %s: %v", secret, err)
		}
		network.WWWDownloads.Store("name:"+secret, &network.WWWDownload{
			Name: secret, AgentUUID: agent.UUID, OperatorSession: client.SessionID,
		})
		got = runC2Command(t, agent, doneChan, agentOut, "download "+secret)
		if !strings.Contains(got, "downloaded") {
			t.Fatalf("registered file was not served: %q", got)
		}
	})

	t.Run("download-refuses-other-agents-token", func(t *testing.T) {
		other := fmt.Sprintf("%d.bin", time.Now().UnixNano())
		if err := os.WriteFile(filepath.Join(paths.WWWRoot, other), []byte("for someone else"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		const otherAgent = "00000000-0000-4000-8000-000000000000"
		if err := client.RegisterWWWDownload(other, otherAgent, 16, ""); err != nil {
			t.Fatalf("register %s: %v", other, err)
		}
		network.WWWDownloads.Store("name:"+other, &network.WWWDownload{
			Name: other, AgentUUID: otherAgent, OperatorSession: client.SessionID,
		})
		got := runC2Command(t, agent, doneChan, agentOut, "download "+other)
		if !strings.Contains(got, "download failed") {
			t.Fatalf("a download registered for another agent was served: %q", got)
		}
	})

	t.Run("download-token-is-one-shot", func(t *testing.T) {
		payload := []byte("one shot body")
		name := fmt.Sprintf("%d.bin", time.Now().UnixNano())
		if err := os.WriteFile(filepath.Join(paths.WWWRoot, name), payload, 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		if err := client.RegisterWWWDownload(name, agent.UUID, int64(len(payload)), ""); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		network.WWWDownloads.Store("name:"+name, &network.WWWDownload{
			Name: name, AgentUUID: agent.UUID, OperatorSession: client.SessionID,
		})
		if got := runC2Command(t, agent, doneChan, agentOut, "download "+name); !strings.Contains(got, "downloaded") {
			t.Fatalf("first fetch failed: %q", got)
		}
		// The registration was consumed by the transfer, so a second fetch is
		// refused.
		if got := runC2Command(t, agent, doneChan, agentOut, "download "+name); !strings.Contains(got, "download failed") {
			t.Fatalf("a consumed download token was served again: %q", got)
		}
	})

	// Size sweep: the same body sizes over the operator upload path.
	for _, size := range transferSizes() {
		size := size
		t.Run(fmt.Sprintf("put-%dKiB", size>>10), func(t *testing.T) {
			if !putPayload(t, agent, doneChan, agentOut, size) {
				t.Fatalf("put did not carry %d bytes", size)
			}
		})
	}

	// get_file: bring the largest body back over the FTP route and compare it
	// with what the agent wrote, so both directions are covered end to end.
	t.Run("get_file-round-trip", func(t *testing.T) {
		if os.Getenv("EMP3R0R_E2E_SIZE") != "" {
			t.Skip("single-size run")
		}
		payload := make([]byte, e2eTransferSize)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("generate payload: %v", err)
		}
		src := filepath.Join(t.TempDir(), "roundtrip.bin")
		if err := os.WriteFile(src, payload, 0o600); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		dest := fmt.Sprintf("/tmp/e2e-roundtrip-%d.bin", time.Now().UnixNano())
		t.Cleanup(func() { _ = os.Remove(dest) })
		if err := ftp.PutFile(src, dest, agent); err != nil {
			t.Fatalf("PutFile: %v", err)
		}
		if !waitForFile(t, dest, int64(len(payload)), 90*time.Second, func() {}) {
			t.Fatalf("agent never received %d bytes", len(payload))
		}

		wantDir, wantPath, _, _ := ftp.GenerateGetFilePaths(dest)
		if err := os.MkdirAll(wantDir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", wantDir, err)
		}
		if err := os.Remove(wantPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("clear %s: %v", wantPath, err)
		}
		if err := modules.DownloadGetFile(agent, dest, "", false); err != nil {
			t.Fatalf("DownloadGetFile: %v", err)
		}
		wantSum := fmt.Sprintf("%x", sha256.Sum256(payload))
		if !waitForFileDigest(t, wantPath, int64(len(payload)), wantSum, 3*time.Minute) {
			t.Fatalf("operator never received %d bytes with digest %s", len(payload), wantSum)
		}
		received, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatalf("read %s: %v", wantPath, err)
		}
		if !bytes.Equal(received, payload) {
			first := -1
			for i := range payload {
				if received[i] != payload[i] {
					first = i
					break
				}
			}
			t.Fatalf("get_file round trip mismatch: got %d bytes, want %d, first difference at offset %d (0x%x)",
				len(received), len(payload), first, first)
		}
		t.Logf("get_file: %d bytes arrived on the operator", len(received))
	})

	// The operator `get` command lists a directory through the module and, with
	// --recursive, downloads every file the listing names.
	t.Run("get-recursive", func(t *testing.T) {
		if os.Getenv("EMP3R0R_E2E_SIZE") != "" {
			t.Skip("single-size run")
		}
		dir := fmt.Sprintf("/tmp/e2e-getdir-%d", time.Now().UnixNano())
		names := []string{"a.log", "b.log", "skip.txt"}
		contents := make(map[string][]byte, len(names))
		for i, name := range names {
			payload := []byte(fmt.Sprintf("file-%d-%s", i, name))
			contents[name] = payload
			src := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(src, payload, 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			remote := filepath.Join(dir, name)
			if err := ftp.PutFile(src, remote, agent); err != nil {
				t.Fatalf("PutFile %s: %v", name, err)
			}
			if !waitForFile(t, remote, int64(len(payload)), 30*time.Second, func() {}) {
				t.Fatalf("agent never received %s", name)
			}
		}

		if err := modules.DownloadGetFile(agent, dir, `\.log$`, true); err != nil {
			t.Fatalf("DownloadGetFile recursive: %v", err)
		}
		for _, name := range []string{"a.log", "b.log"} {
			_, savePath, _, _ := ftp.GenerateGetFilePaths(filepath.Join(dir, name))
			got, err := os.ReadFile(savePath)
			if err != nil {
				t.Fatalf("read %s: %v", savePath, err)
			}
			if !bytes.Equal(got, contents[name]) {
				t.Fatalf("%s: got %d bytes, want %d", name, len(got), len(contents[name]))
			}
		}
		_, skipped, _, _ := ftp.GenerateGetFilePaths(filepath.Join(dir, "skip.txt"))
		if _, err := os.Stat(skipped); err == nil {
			t.Fatalf("filter excluded skip.txt but %s exists", skipped)
		}
	})
}

// putPayload sends `size` random bytes from the C2 into the agent with the
// operator `put` command (the same download path a module payload uses) and
// verifies them byte for byte.
func putPayload(t *testing.T, agent *def.Emp3r0rAgent, doneChan <-chan error, agentOut *bytes.Buffer, size int) bool {
	t.Helper()

	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("generate payload: %v", err)
	}
	src := filepath.Join(t.TempDir(), "e2e-payload.bin")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	dest := fmt.Sprintf("/tmp/e2e-put-%d-%d.bin", time.Now().UnixNano(), size)
	t.Cleanup(func() { _ = os.Remove(dest) })

	if err := ftp.PutFile(src, dest, agent); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	ok := waitForFile(t, dest, int64(len(payload)), 90*time.Second, func() {
		select {
		case werr := <-doneChan:
			t.Fatalf("C agent exited during put: %v.\nOutput:\n%s", werr, agentOut.String())
		default:
		}
	})
	if !ok {
		t.Logf("put %d bytes: agent said: %s", size, lastAgentSays(dest))
		return false
	}
	landed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read %s: %v", dest, err)
	}
	if !bytes.Equal(landed, payload) {
		t.Fatalf("put wrote different bytes: got %d, want %d", len(landed), len(payload))
	}
	t.Logf("put: %d bytes arrived on the agent", len(landed))
	return true
}

// waitForFileDigest waits for the transferred file to hold the expected bytes.
// Size alone is not a completion signal: the receiver pre-allocates the
// destination before the upload starts.
func waitForFileDigest(t *testing.T, path string, size int64, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if fi, err := os.Stat(path); err == nil && fi.Size() == size {
			if sum, serr := fileDigest(path); serr == nil && sum == want {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// fileDigest hashes a file without holding it in memory.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// lastAgentSays returns the most recent agent output that mentions needle, so a
// failed transfer reports what the agent actually saw.
func lastAgentSays(needle string) string {
	var out []string
	live.CmdResults.Range(func(_, v any) bool {
		s, ok := v.(string)
		if ok && (needle == "" || strings.Contains(s, needle)) {
			out = append(out, s)
		}
		return true
	})
	if len(out) == 0 {
		return "(no agent response captured)"
	}
	return out[len(out)-1]
}

// waitForFile waits until path holds exactly size bytes and reports whether it
// got there.
func waitForFile(t *testing.T, path string, size int64, timeout time.Duration, failFast func()) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		failFast()
		if fi, err := os.Stat(path); err == nil && fi.Size() == size {
			return true
		}
		if time.Now().After(deadline) {
			fi, _ := os.Stat(path)
			got := int64(-1)
			if fi != nil {
				got = fi.Size()
			}
			part, _ := os.Stat(path + ".part")
			partSize := int64(-1)
			if part != nil {
				partSize = part.Size()
			}
			t.Logf("%s did not reach %d bytes within %s (size %d, .part %d)",
				path, size, timeout, got, partSize)
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}
