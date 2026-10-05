//go:build !plan9

package socks0_test

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
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

// A reset at any byte of the replies is KindReset; a real TCP RST mid-reply too, or EOF.
func TestHandshakeReset(t *testing.T) {
	rst := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	msgs := serverMsgs(true, "192.0.2.1:1")
	for _, mode := range modes {
		for k := range len(msgs) {
			mc := newMem(msgs[:k])
			mc.rst = rst
			if _, err := hsRun(t, mc, mode, upAuth, true, nil); !errors.Is(err, syscall.ECONNRESET) || socks0.KindOf(err) != socks0.KindReset {
				t.Errorf("%v k=%d: %v kind %q", mode, k, err, socks0.KindOf(err))
			}
		}
		addr := listen(t, func(c net.Conn) {
			c.Read(make([]byte, 512))
			c.Write([]byte{5, 0, 5}) // method + 1 reply byte
			time.Sleep(10 * time.Millisecond)
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		})
		err := handshakeErr(t.Context(), &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode}}, "example.com:80")
		if k := socks0.KindOf(err); k != socks0.KindReset && k != socks0.KindEOF || handshakeErrOf(t, err).Stage != wire.StageReply {
			t.Errorf("%v: %v kind %q", mode, err, k)
		}
	}
}
