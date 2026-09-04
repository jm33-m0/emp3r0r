package script

// Windows-only functional test for the file-streaming primitives used by the
// cifs_upload module (core/modules/cifs_upload/cifs_upload.star):
//
//   cstring_ptr(content)   – binary-safe copy of payload bytes into VirtualAlloc
//   CreateFileW             – open destination (here: local file, same handle
//                             path the module uses for a UNC share)
//   chunked WriteFile       – identical loop to the module's stream_write()
//   GetFileSizeEx           – same verification the module's verify_remote does
//
// A real end-to-end SMB upload needs a reachable share, which CI cannot
// provide; this test proves the byte-exact chunked write pipeline the module
// drives over the redirector works (NUL bytes, >1 chunk, size verification).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cifsTestDriver = `
# mirrors core/modules/cifs_upload/cifs_upload.star: open_dest/stream_write/verify_remote
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

def main(*args):
    path = args[0]
    payload = args[1]   # binary string, may contain NULs
    chunk = int(args[2])
    total = len(payload)

    res = win_call("kernel32.dll", "CreateFileW", path,
                   GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
    h = res["r1"]
    if h == 0 or h == 0xFFFFFFFFFFFFFFFF:
        return "Fail: CreateFileW: %s" % str(res.get("error"))

    buf = cstring_ptr(payload)
    if buf == 0:
        win_call("kernel32.dll", "CloseHandle", h)
        return "Fail: cstring_ptr returned 0"

    written_ptr = win_alloc(4)
    off = 0
    while off < total:
        n = chunk
        if total - off < n:
            n = total - off
        res = win_call("kernel32.dll", "WriteFile", h, buf + off, n, written_ptr, 0)
        if res["r1"] == 0:
            return "Fail: WriteFile @ %d: %s" % (off, str(res.get("error")))
        w = read_uint32(written_ptr, 0)
        if w == 0:
            return "Fail: WriteFile stalled at %d" % off
        off += w

    win_free(written_ptr)
    win_free(buf)
    win_call("kernel32.dll", "CloseHandle", h)

    # verify size the way the module does (verify_remote)
    res = win_call("kernel32.dll", "CreateFileW", path,
                   0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
    h = res["r1"]
    if h == 0 or h == 0xFFFFFFFFFFFFFFFF:
        return "Fail: re-open: %s" % str(res.get("error"))
    size_ptr = win_alloc(8)
    res = win_call("kernel32.dll", "GetFileSizeEx", h, size_ptr)
    size = read_u64(size_ptr, 0)
    win_free(size_ptr)
    win_call("kernel32.dll", "CloseHandle", h)
    if res["r1"] == 0:
        return "Fail: GetFileSizeEx"
    if size != total:
        return "Fail: size mismatch %d != %d" % (size, total)
    return "OK:%d" % size
`

func TestCIFSUploadWritePrimitivesWindows(t *testing.T) {
	dst := filepath.Join(os.TempDir(), "emp3r0r_cifs_upload_test.bin")
	_ = os.Remove(dst)
	defer os.Remove(dst)

	// Binary payload: NULs, high bytes, > 3 chunks of 64KiB (exercise the
	// loop + byte-exactness of cstring_ptr copying).
	payload := make([]byte, 300000)
	for i := range payload {
		payload[i] = byte((i*7 + 13) & 0xFF)
	}
	payload[0] = 0
	payload[1] = 0xDE
	payload[2] = 0xAD
	payload[len(payload)-1] = 0

	out, err := Run([]byte(cifsTestDriver), []string{dst, string(payload), "65536"}, nil, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "OK:300000") {
		t.Fatalf("expected OK:300000, got: %q", out)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("length mismatch: got %d want %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte mismatch at offset %d: got 0x%02x want 0x%02x", i, got[i], payload[i])
		}
	}
}
