package socks0

import (
	"cmp"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

const FastOpenSupported = true

const tcpFastOpenConnect = 30 // TCP_FASTOPEN_CONNECT, Linux 4.11

func fastOpenDial(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	if d != nil {
		nd = *d
	}
	control, controlCtx := nd.Control, nd.ControlContext
	nd.Control = nil
	nd.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		var err error
		switch {
		case controlCtx != nil:
			err = controlCtx(ctx, network, address, c)
		case control != nil:
			err = control(network, address, c)
		}
		if err != nil || !strings.HasPrefix(network, "tcp") {
			return err
		}
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpenConnect, 1)
		}); err != nil {
			return err
		}
		return os.NewSyscallError("setsockopt", serr)
	}
	return nd.DialContext
}

// firstWrite retries through the raw conn a deferred TFO write that failed
// with EINPROGRESS (a safety net; Linux 6.8 does not do this).
func firstWrite(conn net.Conn, b []byte) (int, error) {
	n, err := conn.Write(b)
	if n != 0 || !errors.Is(err, syscall.EINPROGRESS) {
		return n, err
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return n, err
	}
	rc, rerr := sc.SyscallConn()
	if rerr != nil {
		return n, err
	}
	var werr error
	rerr = rc.Write(func(fd uintptr) bool {
		for n < len(b) {
			m, err := syscall.Write(int(fd), b[n:])
			n += max(m, 0)
			switch err {
			case nil, syscall.EINTR:
			case syscall.EAGAIN, syscall.EINPROGRESS:
				return false
			default:
				werr = os.NewSyscallError("write", err)
				return true
			}
		}
		return true
	})
	if werr = cmp.Or(werr, rerr); werr != nil {
		return n, &net.OpError{Op: "write", Net: "tcp", Source: conn.LocalAddr(), Addr: conn.RemoteAddr(), Err: werr}
	}
	return n, nil
}
