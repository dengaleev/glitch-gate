//go:build !plan9

package socks0_test

import (
	"net"
	"os"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

const errnoMapped = true

var (
	eConnRefused error = syscall.ECONNREFUSED
	eConnReset   error = syscall.ECONNRESET
	eMsgSize     error = syscall.EMSGSIZE
	eNoBufs      error = syscall.ENOBUFS
	eDestAddrReq error = syscall.EDESTADDRREQ
)

func errnoIsTests() []isTest {
	return []isTest{
		{rep(1), syscall.ECONNREFUSED, false},
		{rep(3), syscall.ENETUNREACH, true},
		{rep(4), syscall.EHOSTUNREACH, true},
		{rep(5), syscall.ECONNREFUSED, true},
		{rep(6), syscall.ETIMEDOUT, true},
		{rep(5), syscall.ETIMEDOUT, false},
	}
}

func errnoKindTests() []kindTest {
	sys := func(errno syscall.Errno) error {
		return hs(socks0.StageProxyDial, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", errno)})
	}
	return []kindTest{
		{sys(syscall.ECONNREFUSED), socks0.KindRefused},
		{sys(syscall.ECONNRESET), socks0.KindReset},
		{sys(syscall.ECONNABORTED), socks0.KindReset},
		{sys(syscall.EPIPE), socks0.KindReset},
		{sys(syscall.ENETUNREACH), socks0.KindUnreachable},
		{sys(syscall.EHOSTUNREACH), socks0.KindUnreachable},
		{sys(syscall.EINVAL), socks0.KindNetwork},
	}
}
