package c2transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// startTestFileServer starts a minimal P2P file server that speaks the mesh bridge
// protocol (OpcodeFileRequest = 0x03) over mTLS. Returns the listening port string.
func startTestFileServer(t *testing.T, ctx context.Context) string {
	t.Helper()

	tr := transport.GetTransportImplementation("mtls")
	if camo, ok := tr.(*transport.CamouflageMTLS); ok {
		camo.CertOrg = common.RuntimeConfig.CamouflageCertOrg
		camo.CertCN = common.RuntimeConfig.CamouflageCertCN
	}

	// Pick a random free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)
	l.Close()

	listener, err := tr.Listen(port, common.RuntimeConfig.Password, def.MagicString)
	if err != nil {
		t.Fatalf("startTestFileServer listen on %s: %v", port, err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		for ctx.Err() == nil {
			conn, err := tr.Accept(ctx, listener)
			if err != nil {
				return
			}
			go serveTestFileConn(conn)
		}
	}()

	// Wait for listener to be ready
	for range 50 {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return port
}

// serveTestFileConn handles one incoming connection using the bridge protocol.
func serveTestFileConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	op := make([]byte, 1)
	if _, err := conn.Read(op); err != nil {
		return
	}

	switch op[0] {
	case 0x02: // ping
		conn.Write([]byte{0x00})
	case 0x03: // file request
		// Read 4-byte LE filename length
		lenBuf := make([]byte, 4)
		if _, err := readFull(conn, lenBuf); err != nil {
			return
		}
		nameLen := binary.LittleEndian.Uint32(lenBuf)
		nameBuf := make([]byte, nameLen)
		if _, err := readFull(conn, nameBuf); err != nil {
			return
		}
		filename := string(nameBuf)

		conn.SetDeadline(time.Time{})
		data, err := util.ReadFileAgent(filename)
		if err != nil {
			// OpcodeErr
			msg := []byte(err.Error())
			lenBuf2 := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenBuf2, uint16(len(msg)))
			conn.Write([]byte{0xFF})
			conn.Write(lenBuf2)
			conn.Write(msg)
			return
		}
		// OpcodeOK + 4-byte LE data len + data
		dataLenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataLenBuf, uint32(len(data)))
		conn.Write([]byte{0x00})
		conn.Write(dataLenBuf)
		conn.Write(data)
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestFileTransfer_EndToEnd(t *testing.T) {
	common.RuntimeConfig = &def.Config{
		Password:          "e2e_test_password_123",
		P2PTransport:      "mtls",
		CamouflageCertOrg: "emp3r0r test org",
		CamouflageCertCN:  "emp3r0r test cn",
		KCPServerPort:     "", // will be set per sub-test
	}

	testKey := []byte("12345678901234567890123456789012")
	util.SetFileCryptoKey(testKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the test server
	serverPort := startTestFileServer(t, ctx)
	common.RuntimeConfig.KCPServerPort = serverPort

	// Create a test file on disk
	fileName := fmt.Sprintf("e2e_transfer_%d.txt", time.Now().UnixNano())
	safeFilePath := filepath.Join(os.TempDir(), fileName)
	testContent := []byte("Real end-to-end P2P file transfer test content! 123456789")
	if err := util.WriteFileAgent(safeFilePath, testContent, 0o600); err != nil {
		t.Fatalf("write test source file: %v", err)
	}
	defer os.Remove(safeFilePath)
	checksum := crypto.SHA256SumRaw(testContent)

	t.Run("Disk Transfer End-to-End", func(t *testing.T) {
		destDir, err := os.MkdirTemp("", "dl_disk_test")
		if err != nil {
			t.Fatalf("create temp dest dir: %v", err)
		}
		defer os.RemoveAll(destDir)
		destPath := filepath.Join(destDir, "downloaded.txt")

		_, err = FetchFilePeer("127.0.0.1", safeFilePath, destPath, checksum)
		if err != nil {
			t.Fatalf("FetchFilePeer disk: %v", err)
		}

		got, err := util.ReadFileAgent(destPath)
		if err != nil {
			t.Fatalf("read downloaded disk file: %v", err)
		}
		if string(got) != string(testContent) {
			t.Fatalf("disk content mismatch: got %q want %q", got, testContent)
		}
		t.Logf("FetchFilePeer: saved %s to %s (%d bytes)", safeFilePath, destPath, len(got))
	})

	t.Run("MemFS Virtual Memory Transfer End-to-End", func(t *testing.T) {
		destMemPath := fmt.Sprintf("mem:///downloaded_%d.txt", time.Now().UnixNano())

		_, err := FetchFilePeer("127.0.0.1", safeFilePath, destMemPath, checksum)
		if err != nil {
			t.Fatalf("FetchFilePeer mem: %v", err)
		}

		got, err := util.ReadFileAgent(destMemPath)
		if err != nil {
			t.Fatalf("read downloaded mem:/// file: %v", err)
		}
		if string(got) != string(testContent) {
			t.Fatalf("mem content mismatch: got %q want %q", got, testContent)
		}
		t.Logf("FetchFilePeer: saved %s to %s (%d bytes)", safeFilePath, destMemPath, len(got))
	})

	t.Run("Serving From MemFS End-to-End", func(t *testing.T) {
		memFileName := fmt.Sprintf("mem:///hosted_%d.txt", time.Now().UnixNano())
		memContent := []byte("Content stored inside host agent memfs virtual filesystem!")
		if err := util.WriteFileAgent(memFileName, memContent, 0o600); err != nil {
			t.Fatalf("write to memfs: %v", err)
		}

		memChecksum := crypto.SHA256SumRaw(memContent)
		destMemPath := fmt.Sprintf("mem:///received_from_memfs_%d.txt", time.Now().UnixNano())

		_, err := FetchFilePeer("127.0.0.1", memFileName, destMemPath, memChecksum)
		if err != nil {
			t.Fatalf("FetchFilePeer memfs source: %v", err)
		}

		got, err := util.ReadFileAgent(destMemPath)
		if err != nil {
			t.Fatalf("read received memfs file: %v", err)
		}
		if string(got) != string(memContent) {
			t.Fatalf("memfs transfer mismatch: got %q want %q", got, memContent)
		}
		t.Logf("FetchFilePeer: saved %s to %s (%d bytes)", memFileName, destMemPath, len(got))
	})
}
