//go:build linux && (386 || amd64 || arm || arm64) && !no_uring

package uring

import (
	"encoding/binary"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These tests pin the io_uring wire format (SQE field placement, CQE decoding,
// params parsing) using a ring backed by plain slices. They run even on hosts
// whose seccomp policy refuses io_uring_setup, so the encoding cannot silently
// regress where the end-to-end tests are skipped.

const (
	testSQHead     = 0
	testSQTail     = 4
	testSQRingMask = 8
	testSQArray    = 64

	testCQHead     = 0
	testCQTail     = 4
	testCQRingMask = 8
	testCQCQEs     = 32
)

// fakeRing builds a ring over ordinary slices and a synthetic params layout.
func fakeRing(t *testing.T, entries uint32) *ring {
	t.Helper()
	sqRing := make([]byte, int(testSQArray)+int(entries)*4)
	cqRing := make([]byte, int(testCQCQEs)+int(entries)*cqeSize)
	sqes := make([]byte, int(entries)*sqeSize)

	binary.LittleEndian.PutUint32(sqRing[testSQRingMask:], entries-1)
	binary.LittleEndian.PutUint32(cqRing[testCQRingMask:], entries-1)

	p := ringParams{
		sqEntries:  entries,
		cqEntries:  entries,
		features:   featSingleMmap,
		sqHead:     testSQHead,
		sqTail:     testSQTail,
		sqRingMask: testSQRingMask,
		sqArray:    testSQArray,
		cqHead:     testCQHead,
		cqTail:     testCQTail,
		cqRingMask: testCQRingMask,
		cqCQEs:     testCQCQEs,
	}
	r := &ring{fd: -1, sqRing: sqRing, cqRing: cqRing, sqes: sqes}
	r.attach(p, true)
	return r
}

// submission records the last SQE handed to the fake kernel.
type submission struct {
	count uintptr
	sqe   []byte
}

// installEnter replaces io_uring_enter(2) with a fake that captures the last
// submitted SQE and posts one completion.
func installEnter(t *testing.T, r *ring, res int32) *submission {
	t.Helper()
	s := &submission{}
	orig := ioUringEnter
	t.Cleanup(func() { ioUringEnter = orig })
	ioUringEnter = func(_ int, toSubmit, _, _ uintptr) syscall.Errno {
		if toSubmit > 0 {
			s.count += toSubmit
			s.sqe = append([]byte(nil), r.sqes[:sqeSize]...)
		}
		postCQE(r, res)
		return 0
	}
	return s
}

func postCQE(r *ring, res int32) {
	tail := atomic.LoadUint32(r.cqTail)
	idx := int(tail & *r.cqMask)
	base := r.cqes + idx*cqeSize
	binary.LittleEndian.PutUint32(r.cqRing[base+8:], uint32(res))
	atomic.StoreUint32(r.cqTail, tail+1)
}

func TestParseParams(t *testing.T) {
	pb := make([]byte, paramLen)
	binary.LittleEndian.PutUint32(pb[0:], 8)
	binary.LittleEndian.PutUint32(pb[4:], 16)
	binary.LittleEndian.PutUint32(pb[paramFeatures:], featSingleMmap)
	binary.LittleEndian.PutUint32(pb[paramSQHead:], 1)
	binary.LittleEndian.PutUint32(pb[paramSQTail:], 2)
	binary.LittleEndian.PutUint32(pb[paramSQRingMask:], 3)
	binary.LittleEndian.PutUint32(pb[paramSQArray:], 4)
	binary.LittleEndian.PutUint32(pb[paramCQHead:], 5)
	binary.LittleEndian.PutUint32(pb[paramCQTail:], 6)
	binary.LittleEndian.PutUint32(pb[paramCQRingMask:], 7)
	binary.LittleEndian.PutUint32(pb[paramCQCQEs:], 8)

	p := parseParams(pb)
	if p.sqEntries != 8 || p.cqEntries != 16 {
		t.Fatalf("entries = %d/%d, want 8/16", p.sqEntries, p.cqEntries)
	}
	if p.features != featSingleMmap {
		t.Fatalf("features = %#x", p.features)
	}
	if p.sqHead != 1 || p.sqTail != 2 || p.sqRingMask != 3 || p.sqArray != 4 {
		t.Fatalf("sq offsets wrong: %+v", p)
	}
	if p.cqHead != 5 || p.cqTail != 6 || p.cqRingMask != 7 || p.cqCQEs != 8 {
		t.Fatalf("cq offsets wrong: %+v", p)
	}
}

func TestOpenatSQEEncoding(t *testing.T) {
	r := fakeRing(t, 4)
	s := installEnter(t, r, 7)

	fd, err := r.openat("/tmp/wire-test", unix.O_WRONLY|unix.O_CREAT, 0o640)
	if err != nil {
		t.Fatalf("openat: %v", err)
	}
	if fd != 7 {
		t.Fatalf("fd = %d, want 7", fd)
	}
	if s.count != 1 {
		t.Fatalf("submitted %d SQEs, want 1", s.count)
	}
	if s.sqe[sqeOpcode] != opOpenat {
		t.Fatalf("opcode = %d, want %d", s.sqe[sqeOpcode], opOpenat)
	}
	if got := int32(binary.LittleEndian.Uint32(s.sqe[sqeFD:])); got != int32(unix.AT_FDCWD) {
		t.Fatalf("fd = %d, want AT_FDCWD(%d)", got, int32(unix.AT_FDCWD))
	}
	if got := binary.LittleEndian.Uint32(s.sqe[sqeOpenFlags:]); got != uint32(unix.O_WRONLY|unix.O_CREAT) {
		t.Fatalf("open_flags = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(s.sqe[sqeLen:]); got != 0o640 {
		t.Fatalf("mode = %#o, want 640", got)
	}
	if got := binary.LittleEndian.Uint64(s.sqe[sqeAddr:]); got == 0 {
		t.Fatal("path address is null")
	}
}

func TestReadSQEEncoding(t *testing.T) {
	r := fakeRing(t, 4)
	buf := make([]byte, 123)
	s := installEnter(t, r, int32(len(buf)))

	n, err := r.read(9, buf, 4096)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("n = %d, want %d", n, len(buf))
	}
	if s.sqe[sqeOpcode] != opRead {
		t.Fatalf("opcode = %d, want %d", s.sqe[sqeOpcode], opRead)
	}
	if got := int32(binary.LittleEndian.Uint32(s.sqe[sqeFD:])); got != 9 {
		t.Fatalf("fd = %d, want 9", got)
	}
	if got := binary.LittleEndian.Uint64(s.sqe[sqeAddr:]); got != uint64(uintptr(unsafe.Pointer(&buf[0]))) {
		t.Fatalf("addr = %#x, want buffer address", got)
	}
	if got := binary.LittleEndian.Uint32(s.sqe[sqeLen:]); got != 123 {
		t.Fatalf("len = %d, want 123", got)
	}
	if got := binary.LittleEndian.Uint64(s.sqe[sqeOff:]); got != 4096 {
		t.Fatalf("off = %d, want 4096", got)
	}
}

func TestWriteSQEEncoding(t *testing.T) {
	r := fakeRing(t, 4)
	buf := []byte("payload-bytes")
	s := installEnter(t, r, int32(len(buf)))

	n, err := r.write(11, buf, 8192)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("n = %d, want %d", n, len(buf))
	}
	if s.sqe[sqeOpcode] != opWrite {
		t.Fatalf("opcode = %d, want %d", s.sqe[sqeOpcode], opWrite)
	}
	if got := int32(binary.LittleEndian.Uint32(s.sqe[sqeFD:])); got != 11 {
		t.Fatalf("fd = %d, want 11", got)
	}
	if got := binary.LittleEndian.Uint32(s.sqe[sqeLen:]); got != uint32(len(buf)) {
		t.Fatalf("len = %d, want %d", got, len(buf))
	}
	if got := binary.LittleEndian.Uint64(s.sqe[sqeOff:]); got != 8192 {
		t.Fatalf("off = %d, want 8192", got)
	}
}

func TestCloseSQEEncoding(t *testing.T) {
	r := fakeRing(t, 4)
	s := installEnter(t, r, 0)

	if err := r.closeFD(13); err != nil {
		t.Fatalf("closeFD: %v", err)
	}
	if s.sqe[sqeOpcode] != opClose {
		t.Fatalf("opcode = %d, want %d", s.sqe[sqeOpcode], opClose)
	}
	if got := int32(binary.LittleEndian.Uint32(s.sqe[sqeFD:])); got != 13 {
		t.Fatalf("fd = %d, want 13", got)
	}
}

func TestPeekCQEConsumesInOrder(t *testing.T) {
	r := fakeRing(t, 4)
	if _, ok := r.peekCQE(); ok {
		t.Fatal("peek on empty CQ returned a completion")
	}
	postCQE(r, 42)
	postCQE(r, -2)

	if res, ok := r.peekCQE(); !ok || res != 42 {
		t.Fatalf("first completion = (%d, %v), want (42, true)", res, ok)
	}
	if res, ok := r.peekCQE(); !ok || res != -2 {
		t.Fatalf("second completion = (%d, %v), want (-2, true)", res, ok)
	}
	if _, ok := r.peekCQE(); ok {
		t.Fatal("peek after draining returned a completion")
	}
}

func TestGetSQERingFullAndWrap(t *testing.T) {
	r := fakeRing(t, 2)
	if r.getSQE() == nil || r.getSQE() == nil {
		t.Fatal("expected two available SQE slots")
	}
	if r.getSQE() != nil {
		t.Fatal("getSQE returned a slot on a full ring")
	}

	// Simulate the kernel consuming the first entry, then claim another; it
	// must reuse slot 0 and republish the SQ array entry.
	atomic.StoreUint32(r.sqHead, 1)
	sqe := r.getSQE()
	if sqe == nil {
		t.Fatal("getSQE returned nil after space was freed")
	}
	if r.sqArray[0] != 0 {
		t.Fatalf("sq_array[0] = %d, want 0", r.sqArray[0])
	}
}
