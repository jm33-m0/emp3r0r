//go:build linux && (386 || amd64 || arm || arm64) && !no_uring

// Package uring implements a minimal raw io_uring file I/O path.
//
// io_uring requests are serviced by kernel workers and never enter through the
// __x64_sys_openat / __x64_sys_read / __x64_sys_write entry points, so file
// access performed here stays clear of the syscall-entry hooks (kprobes,
// livepatch, tracepoints) that Linux security tooling commonly installs.
//
// io_uring is not universally available, so the exported helpers fall back to
// package os when the ring cannot be used at all — an old kernel, io_uring
// disabled by sysctl, the syscalls blocked by seccomp — and also when a kernel
// accepts io_uring_setup but rejects an individual opcode (for example
// IORING_OP_OPENAT only exists from 5.6, while this project targets 5.4). The
// fallback is the ordinary os path, which is functionally equivalent; there is
// no way to keep the syscall-entry bypass once io_uring is refused, so the
// priority is correctness. Callers never branch on availability.
//
// A ring is created per operation. Agent file I/O is rare, and a short-lived
// ring keeps kernel resources from lingering in the agent, which matters more
// here than amortizing the few microseconds of ring setup. All operations are
// submitted and reaped one at a time, so no per-ring concurrency is possible:
// the package is safe for concurrent callers because each call owns its ring.
package uring

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// io_uring ABI. The linux/io_uring.h layout is stable across the kernels this
// project targets (5.4+); these constants mirror that header. All supported
// build targets are little-endian, so a fixed little-endian codec is used.
const (
	// mmap offsets.
	offSQRing = 0x0
	offCQRing = 0x8000000
	offSQEs   = 0x10000000

	enterGetEvents = 1

	featSingleMmap = 1 << 0

	// Opcodes used here.
	opOpenat = 18
	opClose  = 19
	opRead   = 22
	opWrite  = 23

	sqeSize = 64
	cqeSize = 16

	// struct io_uring_sqe field offsets.
	sqeOpcode    = 0
	sqeFD        = 4
	sqeOff       = 8
	sqeAddr      = 16
	sqeLen       = 24
	sqeOpenFlags = 28

	// struct io_uring_params layout.
	paramLen        = 120
	paramFeatures   = 20
	paramSQHead     = 40
	paramSQTail     = 44
	paramSQRingMask = 48
	paramSQArray    = 64
	paramCQHead     = 80
	paramCQTail     = 84
	paramCQRingMask = 88
	paramCQCQEs     = 100

	// defaultRingEntries stays small: operations are submitted and reaped one
	// at a time, so only a couple of slots are ever live.
	defaultRingEntries = 8

	// writeChunk caps a single SQE payload; larger buffers are split so a
	// multi-megabyte write cannot overflow the u32 len field or stall a worker.
	writeChunk = 1 << 20
	// readChunk is the per-SQE read size when draining a file.
	readChunk = 256 * 1024
)

// errUnavailable marks a failure that means io_uring cannot be used at all on
// this host. It is what triggers the transparent os fallback; per-operation
// errors (ENOENT, EACCES on one file, ...) never carry it, so a single failed
// open cannot disable io_uring for the whole agent.
var errUnavailable = errors.New("io_uring unavailable")

const (
	stateUnknown int32 = iota
	stateAvailable
	stateUnavailable
)

// availState caches the probe result: io_uring availability does not change at
// runtime, and re-probing on every file operation would add sycall noise.
var availState int32

// ring is a single-threaded io_uring instance.
type ring struct {
	fd     int
	sqRing []byte
	cqRing []byte
	sqes   []byte

	sqHead  *uint32
	sqTail  *uint32
	sqMask  *uint32
	sqArray []uint32

	cqHead *uint32
	cqTail *uint32
	cqMask *uint32
	cqes   int // byte offset of the CQE array inside cqRing

	sqEntries uint32
	pending   uint32

	singleMmap bool
}

// readFile reads the whole file through io_uring. It returns errUnavailable
// (possibly wrapped) only when the ring itself cannot be created.
func readFile(name string) ([]byte, error) {
	r, err := newRing(defaultRingEntries)
	if err != nil {
		return nil, err
	}
	defer r.release()

	fd, err := r.openat(name, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	var out []byte
	offset := uint64(0)
	for {
		buf := allocStable(readChunk)
		n, rerr := r.read(fd, buf, offset)
		if rerr != nil {
			_ = r.closeFD(fd)
			return nil, &os.PathError{Op: "read", Path: name, Err: rerr}
		}
		if n > 0 {
			out = append(out, buf[:n]...)
			offset += uint64(n)
		}
		if n < readChunk {
			break
		}
	}

	if err := r.closeFD(fd); err != nil {
		return nil, &os.PathError{Op: "close", Path: name, Err: err}
	}
	return out, nil
}

// writeFile writes data through io_uring, creating/truncating the file.
func writeFile(name string, data []byte, perm uint32) error {
	r, err := newRing(defaultRingEntries)
	if err != nil {
		return err
	}
	defer r.release()

	fd, err := r.openat(name, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, perm)
	if err != nil {
		return err
	}

	offset := uint64(0)
	for len(data) > 0 {
		n := min(len(data), writeChunk)
		written, werr := r.write(fd, data[:n], offset)
		if werr != nil {
			_ = r.closeFD(fd)
			return &os.PathError{Op: "write", Path: name, Err: werr}
		}
		if written == 0 {
			_ = r.closeFD(fd)
			return &os.PathError{Op: "write", Path: name, Err: syscall.EIO}
		}
		data = data[written:]
		offset += uint64(written)
	}

	if err := r.closeFD(fd); err != nil {
		return &os.PathError{Op: "close", Path: name, Err: err}
	}
	return nil
}

// appendFile appends data through io_uring. A -1 offset makes each write use
// the current file position, which honours O_APPEND.
func appendFile(name string, data []byte, perm uint32) error {
	r, err := newRing(defaultRingEntries)
	if err != nil {
		return err
	}
	defer r.release()

	fd, err := r.openat(name, unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND, perm)
	if err != nil {
		return err
	}

	offset := ^uint64(0)
	for len(data) > 0 {
		n := min(len(data), writeChunk)
		written, werr := r.write(fd, data[:n], offset)
		if werr != nil {
			_ = r.closeFD(fd)
			return &os.PathError{Op: "write", Path: name, Err: werr}
		}
		if written == 0 {
			_ = r.closeFD(fd)
			return &os.PathError{Op: "write", Path: name, Err: syscall.EIO}
		}
		data = data[written:]
	}

	if err := r.closeFD(fd); err != nil {
		return &os.PathError{Op: "close", Path: name, Err: err}
	}
	return nil
}

// ringParams is the subset of struct io_uring_params this package needs.
type ringParams struct {
	sqEntries  uint32
	cqEntries  uint32
	features   uint32
	sqHead     uint32
	sqTail     uint32
	sqRingMask uint32
	sqArray    uint32
	cqHead     uint32
	cqTail     uint32
	cqRingMask uint32
	cqCQEs     uint32
}

// parseParams decodes struct io_uring_params as laid out by linux/io_uring.h.
func parseParams(pb []byte) ringParams {
	return ringParams{
		sqEntries:  le32(pb[0:]),
		cqEntries:  le32(pb[4:]),
		features:   le32(pb[paramFeatures:]),
		sqHead:     le32(pb[paramSQHead:]),
		sqTail:     le32(pb[paramSQTail:]),
		sqRingMask: le32(pb[paramSQRingMask:]),
		sqArray:    le32(pb[paramSQArray:]),
		cqHead:     le32(pb[paramCQHead:]),
		cqTail:     le32(pb[paramCQTail:]),
		cqRingMask: le32(pb[paramCQRingMask:]),
		cqCQEs:     le32(pb[paramCQCQEs:]),
	}
}

// newRing creates and maps an io_uring instance.
func newRing(entries uint32) (*ring, error) {
	// The kernel writes a u64-containing struct here, so back it with uint64
	// storage to guarantee the required alignment on 32-bit targets.
	params := make([]uint64, paramLen/8)
	pb := unsafe.Slice((*byte)(unsafe.Pointer(&params[0])), paramLen)

	fd, errno := ioUringSetup(entries, unsafe.Pointer(&params[0]))
	if errno != 0 {
		return nil, wrapUnavailableIfMachinery(errno)
	}

	r := &ring{fd: int(fd)}
	if err := r.mapRing(parseParams(pb)); err != nil {
		r.release()
		return nil, err
	}
	return r, nil
}

// mapRing maps the SQ/CQ rings and SQE array and wires the shared-memory
// pointers for a freshly set-up ring.
func (r *ring) mapRing(p ringParams) error {
	sqRingSz := int(p.sqArray) + int(p.sqEntries)*4
	cqRingSz := int(p.cqCQEs) + int(p.cqEntries)*cqeSize
	prot := unix.PROT_READ | unix.PROT_WRITE
	flags := unix.MAP_SHARED | unix.MAP_POPULATE

	single := p.features&featSingleMmap != 0
	if single {
		// SQ and CQ share one mapping; the CQ offsets are relative to it.
		mem, err := unix.Mmap(r.fd, offSQRing, max(sqRingSz, cqRingSz), prot, flags)
		if err != nil {
			return wrapUnavailableIfMachineryErr(err)
		}
		r.sqRing = mem
		r.cqRing = mem
	} else {
		sq, err := unix.Mmap(r.fd, offSQRing, sqRingSz, prot, flags)
		if err != nil {
			return wrapUnavailableIfMachineryErr(err)
		}
		r.sqRing = sq
		cq, err := unix.Mmap(r.fd, offCQRing, cqRingSz, prot, flags)
		if err != nil {
			return wrapUnavailableIfMachineryErr(err)
		}
		r.cqRing = cq
	}
	// Publish the mapping mode before any fallible step so release() never
	// unmaps the same shared region twice if the SQE map fails below.
	r.singleMmap = single

	sqes, err := unix.Mmap(r.fd, offSQEs, int(p.sqEntries)*sqeSize, prot, flags)
	if err != nil {
		return wrapUnavailableIfMachineryErr(err)
	}
	r.sqes = sqes
	r.attach(p, single)
	return nil
}

// attach wires the ring's shared-memory pointers. The backing buffers must
// already be mapped (production) or supplied by a test.
func (r *ring) attach(p ringParams, single bool) {
	r.sqEntries = p.sqEntries
	r.sqHead = ptrU32(r.sqRing, p.sqHead)
	r.sqTail = ptrU32(r.sqRing, p.sqTail)
	r.sqMask = ptrU32(r.sqRing, p.sqRingMask)
	r.sqArray = unsafe.Slice(ptrU32(r.sqRing, p.sqArray), p.sqEntries)
	r.cqHead = ptrU32(r.cqRing, p.cqHead)
	r.cqTail = ptrU32(r.cqRing, p.cqTail)
	r.cqMask = ptrU32(r.cqRing, p.cqRingMask)
	r.cqes = int(p.cqCQEs)
	r.singleMmap = single
}

// getSQE claims the next submission slot and zeroes it.
func (r *ring) getSQE() []byte {
	tail := atomic.LoadUint32(r.sqTail)
	head := atomic.LoadUint32(r.sqHead)
	if tail-head >= r.sqEntries {
		return nil
	}
	idx := tail & *r.sqMask
	sqe := r.sqes[int(idx)*sqeSize : int(idx+1)*sqeSize]
	for i := range sqe {
		sqe[i] = 0
	}
	// The SQ array maps an entry index to the SQE slot consumed at that
	// position; for a linear ring the two are the same.
	r.sqArray[idx] = idx
	atomic.StoreUint32(r.sqTail, tail+1)
	r.pending++
	return sqe
}

// ioUringSetup performs the io_uring_setup(2) syscall. It is a package
// variable so tests can simulate a host that refuses io_uring and verify the
// fallback.
var ioUringSetup = func(entries uint32, params unsafe.Pointer) (int, syscall.Errno) {
	fd, _, errno := unix.Syscall6(unix.SYS_IO_URING_SETUP, uintptr(entries), uintptr(params), 0, 0, 0, 0)
	return int(fd), errno
}

// ioUringEnter performs the io_uring_enter(2) syscall. It is a package
// variable so tests can drive the ring on hosts where the kernel blocks
// io_uring entirely.
var ioUringEnter = func(fd int, toSubmit, minComplete, flags uintptr) syscall.Errno {
	_, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(fd), toSubmit, minComplete, flags, 0, 0)
	return errno
}

// submitOne submits all pending SQEs and blocks for one completion.
func (r *ring) submitOne() (int32, error) {
	for {
		toSubmit := r.pending
		errno := ioUringEnter(r.fd, uintptr(toSubmit), 1, enterGetEvents)
		if errno != 0 {
			if errno == unix.EINTR {
				// The submission may or may not have been consumed; the
				// kernel only ever takes SQEs between head and tail, so
				// re-entering with the same count is safe.
				continue
			}
			return 0, wrapUnavailableIfMachinery(errno)
		}
		r.pending = 0
		if res, ok := r.peekCQE(); ok {
			return res, nil
		}
	}
}

// peekCQE reaps one completion in submission order.
func (r *ring) peekCQE() (int32, bool) {
	head := atomic.LoadUint32(r.cqHead)
	tail := atomic.LoadUint32(r.cqTail)
	if head == tail {
		return 0, false
	}
	idx := int(head & *r.cqMask)
	base := r.cqes + idx*cqeSize
	res := int32(le32(r.cqRing[base+8:]))
	// Only res/flags are read; the CQE tail is published after the payload by
	// the kernel, and advancing head acknowledges it.
	atomic.StoreUint32(r.cqHead, head+1)
	return res, true
}

func (r *ring) openat(path string, flags int, perm uint32) (int, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	sqe := r.getSQE()
	if sqe == nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: syscall.EAGAIN}
	}
	sqe[sqeOpcode] = opOpenat
	dfd := int32(unix.AT_FDCWD)
	le32Put(sqe[sqeFD:], uint32(dfd))
	le64Put(sqe[sqeAddr:], uint64(uintptr(unsafe.Pointer(p))))
	le32Put(sqe[sqeOpenFlags:], uint32(flags))
	le32Put(sqe[sqeLen:], perm)

	res, err := r.submitOne()
	runtime.KeepAlive(p)
	if err != nil {
		return 0, err
	}
	if res < 0 {
		return 0, &os.PathError{Op: "open", Path: path, Err: opResultErr(syscall.Errno(-res))}
	}
	return int(res), nil
}

func (r *ring) read(fd int, buf []byte, offset uint64) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	sqe := r.getSQE()
	if sqe == nil {
		return 0, syscall.EAGAIN
	}
	sqe[sqeOpcode] = opRead
	le32Put(sqe[sqeFD:], uint32(int32(fd)))
	le64Put(sqe[sqeAddr:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	le32Put(sqe[sqeLen:], uint32(len(buf)))
	le64Put(sqe[sqeOff:], offset)

	res, err := r.submitOne()
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if res < 0 {
		return 0, opResultErr(syscall.Errno(-res))
	}
	return int(res), nil
}

func (r *ring) write(fd int, buf []byte, offset uint64) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	sqe := r.getSQE()
	if sqe == nil {
		return 0, syscall.EAGAIN
	}
	sqe[sqeOpcode] = opWrite
	le32Put(sqe[sqeFD:], uint32(int32(fd)))
	le64Put(sqe[sqeAddr:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	le32Put(sqe[sqeLen:], uint32(len(buf)))
	le64Put(sqe[sqeOff:], offset)

	res, err := r.submitOne()
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if res < 0 {
		return 0, opResultErr(syscall.Errno(-res))
	}
	return int(res), nil
}

func (r *ring) closeFD(fd int) error {
	sqe := r.getSQE()
	if sqe == nil {
		return syscall.EAGAIN
	}
	sqe[sqeOpcode] = opClose
	le32Put(sqe[sqeFD:], uint32(int32(fd)))

	res, err := r.submitOne()
	if err != nil {
		return err
	}
	if res < 0 {
		return opResultErr(syscall.Errno(-res))
	}
	return nil
}

// release unmaps the rings and closes the io_uring fd. It is safe to call on a
// partially initialized ring (setup error) and must not be called twice.
func (r *ring) release() {
	if r.sqRing != nil {
		_ = unix.Munmap(r.sqRing)
	}
	if !r.singleMmap && r.cqRing != nil {
		_ = unix.Munmap(r.cqRing)
	}
	if r.sqes != nil {
		_ = unix.Munmap(r.sqes)
	}
	if r.fd > 0 {
		_ = unix.Close(r.fd)
		r.fd = -1
	}
}

// ReadFile reads name, using io_uring when available and package os otherwise.
func ReadFile(name string) ([]byte, error) {
	if !enabled() {
		return os.ReadFile(name)
	}
	data, err := readFile(name)
	if err == nil {
		return data, nil
	}
	if errors.Is(err, errUnavailable) {
		markUnavailable()
		return os.ReadFile(name)
	}
	return nil, err
}

// WriteFile writes data to name with perm, using io_uring when available.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	if !enabled() {
		return os.WriteFile(name, data, perm)
	}
	if err := writeFile(name, data, uint32(perm.Perm())); err != nil {
		if errors.Is(err, errUnavailable) {
			markUnavailable()
			return os.WriteFile(name, data, perm)
		}
		return err
	}
	return nil
}

// AppendFile appends data to name, creating it 0600 if needed.
func AppendFile(name string, data []byte) error {
	if !enabled() {
		return osAppend(name, data)
	}
	if err := appendFile(name, data, 0o600); err != nil {
		if errors.Is(err, errUnavailable) {
			markUnavailable()
			return osAppend(name, data)
		}
		return err
	}
	return nil
}

func osAppend(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// enabled reports whether the io_uring path should be attempted. The first
// call probes the kernel and caches the answer. There is deliberately no
// target-side switch: an environment variable would be a brand-identifying
// detection vector, and a host that blocks io_uring is already detected here.
// A build that must never use io_uring is produced with `-tags no_uring`.
func enabled() bool {
	switch atomic.LoadInt32(&availState) {
	case stateAvailable:
		return true
	case stateUnavailable:
		return false
	}

	r, err := newRing(1)
	if err != nil {
		if errors.Is(err, errUnavailable) {
			markUnavailable()
		}
		return false
	}
	r.release()
	atomic.StoreInt32(&availState, stateAvailable)
	return true
}

func markUnavailable() { atomic.StoreInt32(&availState, stateUnavailable) }

// wrapUnavailableIfMachinery tags an errno that means the io_uring machinery
// itself is unusable on this host (as opposed to one file failing), which is
// what permits — and caches — the transparent os fallback.
func wrapUnavailableIfMachinery(errno syscall.Errno) error {
	switch errno {
	case unix.ENOSYS, unix.EPERM, unix.EACCES, unix.EOPNOTSUPP, unix.EINVAL, unix.ENODEV:
		return fmt.Errorf("%w: %v", errUnavailable, errno)
	}
	return errno
}

// wrapUnavailableIfMachineryErr is the error-valued form for mmap failures,
// which x/sys returns as a syscall.Errno.
func wrapUnavailableIfMachineryErr(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if wrapped := wrapUnavailableIfMachinery(errno); errors.Is(wrapped, errUnavailable) {
			return wrapped
		}
	}
	return err
}

// opResultErr classifies an io_uring operation result. A kernel may accept
// io_uring_setup yet reject an opcode it does not implement
// (IORING_OP_OPENAT needs 5.6, for example), which also warrants the fallback.
// A per-file error such as EACCES or ENOENT must be returned as-is so it never
// disables io_uring for every other file.
func opResultErr(errno syscall.Errno) error {
	switch errno {
	case unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL:
		return fmt.Errorf("%w: %v", errUnavailable, errno)
	}
	return errno
}

// allocStable returns a heap-backed buffer for kernel I/O. A stack buffer is
// unsafe here: the SQE holds the buffer address while the kernel may run on
// another CPU, and a growing stack could move it. //go:noinline keeps the
// allocation from being folded into the caller's frame.
//
//go:noinline
func allocStable(n int) []byte {
	if n <= 0 {
		n = 1
	}
	return make([]byte, n)
}

func ptrU32(b []byte, off uint32) *uint32 {
	return (*uint32)(unsafe.Pointer(&b[off]))
}

func le32(b []byte) uint32       { return binary.LittleEndian.Uint32(b) }
func le32Put(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func le64Put(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
