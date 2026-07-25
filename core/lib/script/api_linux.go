//go:build linux

package script

import (
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	"go.starlark.net/starlark"
	"golang.org/x/sys/unix"
)

var (
	allocMapMu sync.RWMutex
	allocMap   = make(map[uintptr][]byte)

	syscallNamesMu sync.RWMutex
	syscallNames   = make(map[string]uintptr)
)

func registerSyscalls(syscalls map[string]uintptr) {
	syscallNamesMu.Lock()
	defer syscallNamesMu.Unlock()
	for name, num := range syscalls {
		syscallNames[name] = num
	}
}

func init() {
	// Register syscalls that exist universally across all Linux architectures
	registerSyscalls(map[string]uintptr{
		"read":                   unix.SYS_READ,
		"write":                  unix.SYS_WRITE,
		"close":                  unix.SYS_CLOSE,
		"fstat":                  unix.SYS_FSTAT,
		"lseek":                  unix.SYS_LSEEK,
		"mprotect":               unix.SYS_MPROTECT,
		"munmap":                 unix.SYS_MUNMAP,
		"brk":                    unix.SYS_BRK,
		"rt_sigaction":           unix.SYS_RT_SIGACTION,
		"rt_sigprocmask":         unix.SYS_RT_SIGPROCMASK,
		"ioctl":                  unix.SYS_IOCTL,
		"pread64":                unix.SYS_PREAD64,
		"pwrite64":               unix.SYS_PWRITE64,
		"readv":                  unix.SYS_READV,
		"writev":                 unix.SYS_WRITEV,
		"sched_yield":            unix.SYS_SCHED_YIELD,
		"mremap":                 unix.SYS_MREMAP,
		"msync":                  unix.SYS_MSYNC,
		"mincore":                unix.SYS_MINCORE,
		"madvise":                unix.SYS_MADVISE,
		"shmget":                 unix.SYS_SHMGET,
		"shmat":                  unix.SYS_SHMAT,
		"shmctl":                 unix.SYS_SHMCTL,
		"nanosleep":              unix.SYS_NANOSLEEP,
		"getitimer":              unix.SYS_GETITIMER,
		"setitimer":              unix.SYS_SETITIMER,
		"getpid":                 unix.SYS_GETPID,
		"sendfile":               unix.SYS_SENDFILE,
		"socket":                 unix.SYS_SOCKET,
		"connect":                unix.SYS_CONNECT,
		"sendto":                 unix.SYS_SENDTO,
		"recvfrom":               unix.SYS_RECVFROM,
		"sendmsg":                unix.SYS_SENDMSG,
		"recvmsg":                unix.SYS_RECVMSG,
		"shutdown":               unix.SYS_SHUTDOWN,
		"bind":                   unix.SYS_BIND,
		"listen":                 unix.SYS_LISTEN,
		"getsockname":            unix.SYS_GETSOCKNAME,
		"getpeername":            unix.SYS_GETPEERNAME,
		"socketpair":             unix.SYS_SOCKETPAIR,
		"setsockopt":             unix.SYS_SETSOCKOPT,
		"getsockopt":             unix.SYS_GETSOCKOPT,
		"clone":                  unix.SYS_CLONE,
		"execve":                 unix.SYS_EXECVE,
		"exit":                   unix.SYS_EXIT,
		"wait4":                  unix.SYS_WAIT4,
		"kill":                   unix.SYS_KILL,
		"uname":                  unix.SYS_UNAME,
		"fcntl":                  unix.SYS_FCNTL,
		"flock":                  unix.SYS_FLOCK,
		"fsync":                  unix.SYS_FSYNC,
		"fdatasync":              unix.SYS_FDATASYNC,
		"truncate":               unix.SYS_TRUNCATE,
		"ftruncate":              unix.SYS_FTRUNCATE,
		"getcwd":                 unix.SYS_GETCWD,
		"chdir":                  unix.SYS_CHDIR,
		"fchdir":                 unix.SYS_FCHDIR,
		"fchmod":                 unix.SYS_FCHMOD,
		"fchown":                 unix.SYS_FCHOWN,
		"umask":                  unix.SYS_UMASK,
		"gettimeofday":           unix.SYS_GETTIMEOFDAY,
		"getrusage":              unix.SYS_GETRUSAGE,
		"sysinfo":                unix.SYS_SYSINFO,
		"times":                  unix.SYS_TIMES,
		"ptrace":                 unix.SYS_PTRACE,
		"getuid":                 unix.SYS_GETUID,
		"getgid":                 unix.SYS_GETGID,
		"setuid":                 unix.SYS_SETUID,
		"setgid":                 unix.SYS_SETGID,
		"geteuid":                unix.SYS_GETEUID,
		"getegid":                unix.SYS_GETEGID,
		"setpgid":                unix.SYS_SETPGID,
		"getppid":                unix.SYS_GETPPID,
		"setsid":                 unix.SYS_SETSID,
		"setreuid":               unix.SYS_SETREUID,
		"setregid":               unix.SYS_SETREGID,
		"getgroups":              unix.SYS_GETGROUPS,
		"setgroups":              unix.SYS_SETGROUPS,
		"getpgid":                unix.SYS_GETPGID,
		"getsid":                 unix.SYS_GETSID,
		"capget":                 unix.SYS_CAPGET,
		"capset":                 unix.SYS_CAPSET,
		"statfs":                 unix.SYS_STATFS,
		"fstatfs":                unix.SYS_FSTATFS,
		"sched_setparam":         unix.SYS_SCHED_SETPARAM,
		"sched_getparam":         unix.SYS_SCHED_GETPARAM,
		"sched_setscheduler":     unix.SYS_SCHED_SETSCHEDULER,
		"sched_getscheduler":     unix.SYS_SCHED_GETSCHEDULER,
		"sched_get_priority_max": unix.SYS_SCHED_GET_PRIORITY_MAX,
		"sched_get_priority_min": unix.SYS_SCHED_GET_PRIORITY_MIN,
		"sched_rr_get_interval":  unix.SYS_SCHED_RR_GET_INTERVAL,
		"mlock":                  unix.SYS_MLOCK,
		"munlock":                unix.SYS_MUNLOCK,
		"mlockall":               unix.SYS_MLOCKALL,
		"munlockall":             unix.SYS_MUNLOCKALL,
		"prctl":                  unix.SYS_PRCTL,
		"chroot":                 unix.SYS_CHROOT,
		"sync":                   unix.SYS_SYNC,
		"settimeofday":           unix.SYS_SETTIMEOFDAY,
		"mount":                  unix.SYS_MOUNT,
		"umount2":                unix.SYS_UMOUNT2,
		"reboot":                 unix.SYS_REBOOT,
		"sethostname":            unix.SYS_SETHOSTNAME,
		"setdomainname":          unix.SYS_SETDOMAINNAME,
		"gettid":                 unix.SYS_GETTID,
		"readahead":              unix.SYS_READAHEAD,
		"tkill":                  unix.SYS_TKILL,
		"futex":                  unix.SYS_FUTEX,
		"sched_setaffinity":      unix.SYS_SCHED_SETAFFINITY,
		"sched_getaffinity":      unix.SYS_SCHED_GETAFFINITY,
		"getdents64":             unix.SYS_GETDENTS64,
		"set_tid_address":        unix.SYS_SET_TID_ADDRESS,
		"clock_settime":          unix.SYS_CLOCK_SETTIME,
		"clock_gettime":          unix.SYS_CLOCK_GETTIME,
		"clock_getres":           unix.SYS_CLOCK_GETRES,
		"clock_nanosleep":        unix.SYS_CLOCK_NANOSLEEP,
		"exit_group":             unix.SYS_EXIT_GROUP,
		"epoll_ctl":              unix.SYS_EPOLL_CTL,
		"tgkill":                 unix.SYS_TGKILL,
		"openat":                 unix.SYS_OPENAT,
		"mkdirat":                unix.SYS_MKDIRAT,
		"mknodat":                unix.SYS_MKNODAT,
		"fchownat":               unix.SYS_FCHOWNAT,
		"unlinkat":               unix.SYS_UNLINKAT,
		"linkat":                 unix.SYS_LINKAT,
		"symlinkat":              unix.SYS_SYMLINKAT,
		"readlinkat":             unix.SYS_READLINKAT,
		"fchmodat":               unix.SYS_FCHMODAT,
		"faccessat":              unix.SYS_FACCESSAT,
		"pselect6":               unix.SYS_PSELECT6,
		"ppoll":                  unix.SYS_PPOLL,
		"unshare":                unix.SYS_UNSHARE,
		"splice":                 unix.SYS_SPLICE,
		"tee":                    unix.SYS_TEE,
		"vmsplice":               unix.SYS_VMSPLICE,
		"utimensat":              unix.SYS_UTIMENSAT,
		"epoll_pwait":            unix.SYS_EPOLL_PWAIT,
		"timerfd_create":         unix.SYS_TIMERFD_CREATE,
		"fallocate":              unix.SYS_FALLOCATE,
		"timerfd_settime":        unix.SYS_TIMERFD_SETTIME,
		"timerfd_gettime":        unix.SYS_TIMERFD_GETTIME,
		"accept4":                unix.SYS_ACCEPT4,
		"signalfd4":              unix.SYS_SIGNALFD4,
		"eventfd2":               unix.SYS_EVENTFD2,
		"epoll_create1":          unix.SYS_EPOLL_CREATE1,
		"dup3":                   unix.SYS_DUP3,
		"pipe2":                  unix.SYS_PIPE2,
		"preadv":                 unix.SYS_PREADV,
		"pwritev":                unix.SYS_PWRITEV,
		"prlimit64":              unix.SYS_PRLIMIT64,
		"getrandom":              unix.SYS_GETRANDOM,
		"memfd_create":           unix.SYS_MEMFD_CREATE,
		"bpf":                    unix.SYS_BPF,
		"execveat":               unix.SYS_EXECVEAT,
		"copy_file_range":        unix.SYS_COPY_FILE_RANGE,
	})

	// Register architecture-specific syscalls
	registerArchSyscalls()
}

const maxSyscallNum = 65535

func parseSyscallNum(val starlark.Value) (uintptr, error) {
	switch v := val.(type) {
	case starlark.Int:
		if num, ok := v.Uint64(); ok {
			if num > maxSyscallNum {
				return 0, fmt.Errorf("syscall number out of valid range (0-%d): %d", maxSyscallNum, num)
			}
			return uintptr(num), nil
		}
		if num, ok := v.Int64(); ok {
			if num < 0 || num > maxSyscallNum {
				return 0, fmt.Errorf("syscall number out of valid range (0-%d): %d", maxSyscallNum, num)
			}
			return uintptr(num), nil
		}
		return 0, fmt.Errorf("invalid syscall number integer")
	case starlark.String:
		str := string(v)
		if num, err := strconv.ParseUint(str, 0, 32); err == nil {
			if num > maxSyscallNum {
				return 0, fmt.Errorf("syscall number out of valid range (0-%d): %d", maxSyscallNum, num)
			}
			return uintptr(num), nil
		}

		syscallNamesMu.RLock()
		num, ok := syscallNames[str]
		if !ok {
			cleanStr := str
			if len(cleanStr) > 4 && (cleanStr[:4] == "sys_" || cleanStr[:4] == "SYS_") {
				cleanStr = cleanStr[4:]
			}
			num, ok = syscallNames[cleanStr]
		}
		syscallNamesMu.RUnlock()

		if ok {
			return num, nil
		}
		return 0, fmt.Errorf("unknown or unsupported syscall name on this arch: %s", str)
	default:
		return 0, fmt.Errorf("syscall number parameter must be integer or string, got %s", val.Type())
	}
}

// starlarkSysCall provides an interface to execute any Linux system call dynamically
func starlarkSysCall(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (retVal starlark.Value, retErr error) {
	if len(args) < 1 {
		return starlark.None, fmt.Errorf("sys_call requires at least a syscall number or name")
	}

	defer func() {
		if r := recover(); r != nil {
			dict := starlark.NewDict(4)
			dict.SetKey(starlark.String("r1"), starlark.MakeUint64(0))
			dict.SetKey(starlark.String("r2"), starlark.MakeUint64(0))
			dict.SetKey(starlark.String("errno"), starlark.MakeInt(1))
			dict.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("sys_call panic: %v", r)))
			retErr = nil
			retVal = dict
		}
	}()

	trap, err := parseSyscallNum(args[0])
	if err != nil {
		return starlark.None, err
	}

	var uintptrArgs [6]uintptr
	var keepAlive []interface{}

	for i := 1; i < len(args) && i <= 6; i++ {
		idx := i - 1
		switch v := args[i].(type) {
		case starlark.Int:
			if val, ok := v.Int64(); ok {
				uintptrArgs[idx] = uintptr(val)
			} else if val, ok := v.Uint64(); ok {
				uintptrArgs[idx] = uintptr(val)
			} else {
				return starlark.None, fmt.Errorf("failed parsing integer argument at index %d", i)
			}
		case starlark.String:
			strVal := string(v)
			cStr := append([]byte(strVal), 0)
			uintptrArgs[idx] = uintptr(unsafe.Pointer(&cStr[0]))
			keepAlive = append(keepAlive, cStr)
		case starlark.Bool:
			if bool(v) {
				uintptrArgs[idx] = 1
			} else {
				uintptrArgs[idx] = 0
			}
		case starlark.NoneType:
			uintptrArgs[idx] = 0
		case *starlark.List:
			n := v.Len()
			buf := make([]byte, n)
			for j := 0; j < n; j++ {
				if itemInt, ok := v.Index(j).(starlark.Int); ok {
					if bVal, ok := itemInt.Int64(); ok {
						buf[j] = byte(bVal)
					}
				}
			}
			if len(buf) > 0 {
				uintptrArgs[idx] = uintptr(unsafe.Pointer(&buf[0]))
				keepAlive = append(keepAlive, buf)
			} else {
				uintptrArgs[idx] = 0
			}
		default:
			return starlark.None, fmt.Errorf("unsupported type parameter passed at index %d: %s", i, args[i].Type())
		}
	}

	r1, r2, sysErr := unix.Syscall6(
		trap,
		uintptrArgs[0], uintptrArgs[1], uintptrArgs[2],
		uintptrArgs[3], uintptrArgs[4], uintptrArgs[5],
	)
	_ = keepAlive

	dict := starlark.NewDict(4)
	dict.SetKey(starlark.String("r1"), starlark.MakeUint64(uint64(r1)))
	dict.SetKey(starlark.String("r2"), starlark.MakeUint64(uint64(r2)))
	dict.SetKey(starlark.String("errno"), starlark.MakeInt(int(sysErr)))

	errStr := ""
	if sysErr != 0 {
		errStr = sysErr.Error()
	}
	dict.SetKey(starlark.String("error"), starlark.String(errStr))

	return dict, nil
}

// starlarkSysAlloc allocates memory via mmap for data exchanges
func starlarkSysAlloc(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "size", &size); err != nil {
		return starlark.None, err
	}
	if size <= 0 {
		return starlark.None, fmt.Errorf("allocation request size must be greater than zero")
	}

	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return starlark.None, fmt.Errorf("sys_alloc memory assignment failed: %w", err)
	}

	addr := uintptr(unsafe.Pointer(&buf[0]))
	allocMapMu.Lock()
	allocMap[addr] = buf
	allocMapMu.Unlock()

	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkSysFree deallocates memory via munmap
func starlarkSysFree(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr); err != nil {
		return starlark.None, err
	}

	allocMapMu.Lock()
	buf, exists := allocMap[uintptr(addr)]
	if exists {
		delete(allocMap, uintptr(addr))
	}
	allocMapMu.Unlock()

	if exists {
		if err := unix.Munmap(buf); err != nil {
			return starlark.None, fmt.Errorf("sys_free munmap failed: %w", err)
		}
	}
	return starlark.None, nil
}

// starlarkSysReadMem copies data out of unmanaged memory back into a script list of bytes
func starlarkSysReadMem(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	var size int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "size", &size); err != nil {
		return starlark.None, err
	}
	if size <= 0 {
		return starlark.None, fmt.Errorf("read range length constraint must be greater than zero")
	}

	allocMapMu.RLock()
	buf, exists := allocMap[uintptr(addr)]
	allocMapMu.RUnlock()

	if !exists {
		return starlark.None, fmt.Errorf("sys_read_mem: unallocated or invalid memory address 0x%x", addr)
	}

	if size > len(buf) {
		size = len(buf)
	}
	src := buf[:size]

	elems := make([]starlark.Value, len(src))
	for i, b := range src {
		elems[i] = starlark.MakeInt(int(b))
	}
	return starlark.NewList(elems), nil
}
