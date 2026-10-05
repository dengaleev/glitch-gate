package socks0_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

const (
	tcpFastOpen        = 23
	tcpFastOpenConnect = 30
	tcpiOptSynData     = 0x20
)

func tfoListen(t *testing.T, handle func(net.Conn)) string {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpen, 16) })
		return serr
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serve(t, ln, handle)
}

func tfoSysctl(t *testing.T) int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fastopen")
	if err != nil {
		t.Skip(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func synData(t *testing.T, c net.Conn) bool {
	if sc, ok := c.(*socks0.Conn); ok {
		c = sc.NetConn()
	}
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info syscall.TCPInfo
	size := uint32(unsafe.Sizeof(info))
	var errno syscall.Errno
	rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	return info.Options&tcpiOptSynData != 0
}

func TestFastOpenDial(t *testing.T) {
	if tfoSysctl(t)&1 == 0 {
		t.Skip("net.ipv4.tcp_fastopen has no client bit")
	}
	server := tfoSysctl(t)&2 != 0
	addr := tfoListen(t, proxy{}.serve)
	var controlled int
	nd := &net.Dialer{Control: func(string, string, syscall.RawConn) error { controlled++; return nil }}
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: addr, ProxyDial: socks0.FastOpenDial(nd), Config: &socks0.Config{Mode: mode}}
			for i := range 3 { // the first dial fetches a cookie
				c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				if s := roundTrip(t, c, "tfo"); s != "tfo" {
					t.Fatalf("echo %q", s)
				}
				rc, _ := c.(interface {
					SyscallConn() (syscall.RawConn, error)
				}).SyscallConn()
				var v int
				rc.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpenConnect) })
				if v != 1 {
					t.Errorf("TCP_FASTOPEN_CONNECT = %d", v)
				}
				if sd := synData(t, c); server && i > 0 && !sd {
					t.Errorf("dial %d: no data in the SYN", i)
				}
				c.Close()
			}
		})
	}
	if controlled != 9 {
		t.Errorf("Control ran %d times", controlled)
	}
}

func TestFastOpenRefused(t *testing.T) {
	if tfoSysctl(t)&1 == 0 {
		t.Skip("net.ipv4.tcp_fastopen has no client bit")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	for _, mode := range modes {
		d := &socks0.Dialer{ProxyAddr: addr, ProxyDial: socks0.FastOpenDial(nil), Config: &socks0.Config{Mode: mode}}
		err := handshakeErr(t.Context(), d, "example.com:80")
		if !errors.Is(err, syscall.ECONNREFUSED) || socks0.KindOf(err) != socks0.KindRefused {
			t.Errorf("%v: err = %v; kind %q", mode, err, socks0.KindOf(err))
		}
	}
}

func TestFastOpenControlError(t *testing.T) {
	dial := socks0.FastOpenDial(&net.Dialer{ControlContext: func(context.Context, string, string, syscall.RawConn) error { return errTest }})
	if _, err := dial(t.Context(), "tcp", "127.0.0.1:1"); !errors.Is(err, errTest) {
		t.Errorf("err = %v", err)
	}
}

// inProgressConn fails its first Write with EINPROGRESS and no bytes, as deferred TFO may.
type inProgressConn struct {
	*net.TCPConn
	failed bool
}

func (c *inProgressConn) Write(b []byte) (int, error) {
	if !c.failed {
		c.failed = true
		return 0, &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EINPROGRESS)}
	}
	return c.TCPConn.Write(b)
}

func TestFirstWriteInProgress(t *testing.T) {
	for _, mode := range modes {
		got := make(chan request, 1)
		d := &socks0.Dialer{
			ProxyAddr: listen(t, proxy{got: got}.serve),
			ProxyDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := new(net.Dialer).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return &inProgressConn{TCPConn: c.(*net.TCPConn)}, nil
			},
			Config: &socks0.Config{Mode: mode},
		}
		c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		if s := roundTrip(t, c, "retried"); s != "retried" {
			t.Errorf("%v: echo %q", mode, s)
		}
		if r := <-got; r.target != mustAddr("example.com:80") {
			t.Errorf("%v: target %v", mode, r.target)
		}
		c.Close()
	}
}
