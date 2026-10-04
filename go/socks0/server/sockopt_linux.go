package server

import (
	"net"
	"syscall"
	"time"
)

const tcpUserTimeout = 0x12 // TCP_USER_TIMEOUT, linux/tcp.h

func setUserTimeout(c net.Conn, d time.Duration) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	if d == defaultUserTimeout {
		_ = rc.Control(setDefaultUserTimeout) // no closure to allocate
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(d.Milliseconds()))
	})
}

func setDefaultUserTimeout(fd uintptr) {
	_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(defaultUserTimeout.Milliseconds()))
}
