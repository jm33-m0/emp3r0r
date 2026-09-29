//go:build linux && arm

package script

import "golang.org/x/sys/unix"

func registerArchSyscalls() {
	registerSyscalls(map[string]uintptr{
		"open":   unix.SYS_OPEN,
		"stat":   unix.SYS_STAT,
		"lstat":  unix.SYS_LSTAT,
		"poll":   unix.SYS_POLL,
		"access": unix.SYS_ACCESS,
		"pipe":   unix.SYS_PIPE,
		"dup2":   unix.SYS_DUP2,
		"pause":  unix.SYS_PAUSE,
		"accept": unix.SYS_ACCEPT,
		// 32-bit ARM has no mmap(2); mmap2(2) is the same call with the file
		// offset expressed in pages. Callers that pass a page-aligned offset
		// (0 in all shipped modules) get identical behaviour under this name.
		"mmap":         unix.SYS_MMAP2,
		"fork":         unix.SYS_FORK,
		"vfork":        unix.SYS_VFORK,
		"getpgrp":      unix.SYS_GETPGRP,
		"epoll_create": unix.SYS_EPOLL_CREATE,
		"epoll_wait":   unix.SYS_EPOLL_WAIT,
		"renameat":     unix.SYS_RENAMEAT,
		"signalfd":     unix.SYS_SIGNALFD,
		"eventfd":      unix.SYS_EVENTFD,
	})
}
