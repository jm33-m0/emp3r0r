//go:build linux && (386 || amd64 || arm || arm64) && !no_uring

package uring

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// requireIOUring skips the test when the host cannot run io_uring at all, and
// otherwise guarantees the package has probed it successfully.
func requireIOUring(t *testing.T) {
	t.Helper()
	atomic.StoreInt32(&availState, stateUnknown)
	r, err := newRing(1)
	if err != nil {
		if errors.Is(err, errUnavailable) {
			t.Skipf("io_uring unavailable on this host: %v", err)
		}
		t.Fatalf("newRing: %v", err)
	}
	r.release()
	if !enabled() {
		t.Fatal("io_uring ring works but enabled() reports unavailable")
	}
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// TestRawRingReadWrite exercises the io_uring read/write path directly, with no
// fallback available, and verifies the bytes round-trip exactly.
func TestRawRingReadWrite(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.bin")
	want := randBytes(t, 300*1024) // > readChunk to force multiple reads

	if err := writeFile(path, want, 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	got, err := readFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}

	// Cross-check against package os so a symmetric bug cannot pass.
	osGot, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if !bytes.Equal(osGot, want) {
		t.Fatal("io_uring wrote different bytes than expected when read back by os")
	}
}

// TestReadFileReadsOSWritten verifies the exported helper consumes files written
// by ordinary means (the common agent case: someone else wrote the file).
func TestReadFileReadsOSWritten(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.txt")
	want := []byte("hello io_uring\nsecond line\x00with nul")
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestWriteFileReadableByOS verifies the exported writer produces a normal file.
func TestWriteFileReadableByOS(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "written.txt")
	want := randBytes(t, 2*1024*1024+17) // > writeChunk to exercise splitting
	if err := WriteFile(path, want, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d", len(got), len(want))
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	} else if fi.Mode().Perm() != 0o640 {
		t.Fatalf("perm = %o, want 640", fi.Mode().Perm())
	}
}

// TestWriteFileTruncates guards against O_TRUNC being dropped: rewriting a file
// with less data must not leave a tail of the old content.
func TestWriteFileTruncates(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.txt")
	if err := WriteFile(path, bytes.Repeat([]byte("A"), 4096), 0o600); err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	if err := WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatalf("second WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if string(got) != "short" {
		t.Fatalf("got %q, want %q", got, "short")
	}
}

// TestAppendFile checks that repeated appends accumulate in order.
func TestAppendFile(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "append.log")
	for _, part := range []string{"one\n", "two\n", "three\n"} {
		if err := AppendFile(path, []byte(part)); err != nil {
			t.Fatalf("AppendFile(%q): %v", part, err)
		}
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "one\ntwo\nthree\n" {
		t.Fatalf("got %q", got)
	}
}

// TestEmptyFile ensures the zero-length edge case is handled (open+truncate).
func TestEmptyFile(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want 0", len(got))
	}
}

// TestBinaryAllByteValues makes sure the raw memory path does not mangle data.
func TestBinaryAllByteValues(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bytes.bin")
	want := make([]byte, 512)
	for i := range want {
		want[i] = byte(i)
	}
	if err := WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("byte values were altered")
	}
}

// TestReadMissingFile verifies error semantics survive the raw path: callers in
// lib/util and lib/script rely on os.IsNotExist working.
func TestReadMissingFile(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")
	_, err := ReadFile(missing)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("os.IsNotExist(%v) = false, want true", err)
	}

	// The raw io_uring path must not silently fall back or swallow the error.
	if _, rawErr := readFile(missing); !os.IsNotExist(rawErr) {
		t.Fatalf("raw readFile missing: os.IsNotExist(%v) = false", rawErr)
	}
}

// TestFallbackOnSetupFailure simulates a kernel that refuses io_uring_setup and
// verifies the exported helpers fall back to os transparently and correctly.
func TestFallbackOnSetupFailure(t *testing.T) {
	origSetup := ioUringSetup
	origState := atomic.LoadInt32(&availState)
	t.Cleanup(func() {
		ioUringSetup = origSetup
		atomic.StoreInt32(&availState, origState)
	})

	ioUringSetup = func(uint32, unsafe.Pointer) (int, syscall.Errno) {
		return -1, unix.ENOSYS
	}
	atomic.StoreInt32(&availState, stateUnknown)

	dir := t.TempDir()
	path := filepath.Join(dir, "fallback-setup.txt")
	want := []byte("setup refused; the os fallback must still work")
	if err := WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("fallback content mismatch")
	}
	// A refused setup must be cached so later calls skip the probe.
	if state := atomic.LoadInt32(&availState); state != stateUnavailable {
		t.Fatalf("availState = %d, want stateUnavailable", state)
	}
}

// TestErrorClassification pins which errnos trigger the fallback. Per-file
// errors must stay per-file so one unreadable file cannot disable io_uring.
func TestErrorClassification(t *testing.T) {
	for _, e := range []syscall.Errno{unix.ENOSYS, unix.EPERM, unix.EACCES, unix.EOPNOTSUPP, unix.EINVAL, unix.ENODEV} {
		if !errors.Is(wrapUnavailableIfMachinery(e), errUnavailable) {
			t.Errorf("machinery errno %v not classified as unavailable", e)
		}
	}
	for _, e := range []syscall.Errno{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP} {
		if !errors.Is(opResultErr(e), errUnavailable) {
			t.Errorf("operation errno %v should trigger the fallback", e)
		}
	}
	for _, e := range []syscall.Errno{unix.EACCES, unix.EPERM, unix.ENOENT, unix.ENOSPC} {
		if errors.Is(opResultErr(e), errUnavailable) {
			t.Errorf("per-file errno %v must not disable io_uring", e)
		}
	}
}

// TestSubmitOneClassifiesEnterFailure verifies that a blocked io_uring_enter is
// reported as unavailability rather than as a plain I/O error.
func TestSubmitOneClassifiesEnterFailure(t *testing.T) {
	r := fakeRing(t, 4)
	orig := ioUringEnter
	t.Cleanup(func() { ioUringEnter = orig })
	ioUringEnter = func(int, uintptr, uintptr, uintptr) syscall.Errno { return unix.ENOSYS }

	if r.getSQE() == nil {
		t.Fatal("getSQE returned nil")
	}
	if _, err := r.submitOne(); !errors.Is(err, errUnavailable) {
		t.Fatalf("submitOne err = %v, want errUnavailable", err)
	}
}

// TestConcurrentFileIO drives the exported API from many goroutines. Each call
// owns its ring, so this validates that no ring state is shared and that the
// package passes -race.
func TestConcurrentFileIO(t *testing.T) {
	requireIOUring(t)
	dir := t.TempDir()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := filepath.Join(dir, string(rune('a'+i))+".bin")
			want := bytes.Repeat([]byte{byte(i)}, 64*1024+i*1024)
			if err := WriteFile(path, want, 0o600); err != nil {
				errs <- err
				return
			}
			got, err := ReadFile(path)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, want) {
				errs <- errors.New("content mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
