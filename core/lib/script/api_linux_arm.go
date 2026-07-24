//go:build linux && arm

package script

import "golang.org/x/sys/unix"

func registerArchSyscalls() {
	registerSyscalls(map[string]uintptr{
		"open":         unix.SYS_OPEN,
		"stat":         unix.SYS_STAT,
		"lstat":        unix.SYS_LSTAT,
		"poll":         unix.SYS_POLL,
		"access":       unix.SYS_ACCESS,
		"pipe":         unix.SYS_PIPE,
		"dup2":         unix.SYS_DUP2,
		"pause":        unix.SYS_PAUSE,
		"accept":       unix.SYS_ACCEPT,
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
