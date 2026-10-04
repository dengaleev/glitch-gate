//go:build !plan9

package socks0_test

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func dialWith(t *testing.T, mode socks0.Mode, dial func(context.Context, string, string) (net.Conn, error)) error {
	t.Helper()
	d := &socks0.Dialer{ProxyAddr: "proxy.example:1080", ProxyDial: dial, Config: &socks0.Config{Mode: mode}}
	return handshakeErr(t.Context(), d, "example.com:80")
}

func TestVerifyKindOfEveryClass(t *testing.T) {
	sysErr := func(e syscall.Errno) func(context.Context, string, string) (net.Conn, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
		}
	}
	closedPort := func() string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		a := ln.Addr().String()
		ln.Close()
		return a
	}()
	cases := []struct {
		name string
		err  func(t *testing.T) error
		want socks0.Kind
	}{
		{"config", func(t *testing.T) error {
			_, err := (&socks0.Dialer{}).DialContext(t.Context(), "unix", "x:1")
			return err
		}, socks0.KindConfig},
		{"refused (real)", func(t *testing.T) error {
			_, err := (&socks0.Dialer{ProxyAddr: closedPort}).DialContext(t.Context(), "tcp", "x:1")
			return err
		}, socks0.KindRefused},
		{"reset", func(t *testing.T) error { return dialWith(t, 0, sysErr(syscall.ECONNRESET)) }, socks0.KindReset},
		{"aborted", func(t *testing.T) error { return dialWith(t, 0, sysErr(syscall.ECONNABORTED)) }, socks0.KindReset},
		{"epipe", func(t *testing.T) error { return dialWith(t, 0, sysErr(syscall.EPIPE)) }, socks0.KindReset},
		{"unreachable net", func(t *testing.T) error { return dialWith(t, 0, sysErr(syscall.ENETUNREACH)) }, socks0.KindUnreachable},
		{"unreachable host", func(t *testing.T) error { return dialWith(t, 0, sysErr(syscall.EHOSTUNREACH)) }, socks0.KindUnreachable},
		{"dns", func(t *testing.T) error {
			return dialWith(t, 0, func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "proxy.example", IsNotFound: true}}
			})
		}, socks0.KindDNS},
		{"network", func(t *testing.T) error {
			return dialWith(t, 0, func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: errors.New("weird")}
			})
		}, socks0.KindNetwork},
		{"other", func(t *testing.T) error {
			return dialWith(t, 0, func(context.Context, string, string) (net.Conn, error) { return nil, errTest })
		}, socks0.KindOther},
		{"timeout deadline (L2 read wait)", func(t *testing.T) error {
			c := socks0.Client(newMem(), "x:1", early())
			c.SetReadDeadline(time.Now().Add(time.Millisecond))
			_, err := c.Read(make([]byte, 1))
			return err
		}, socks0.KindTimeout},
		{"timeout ReplyTimeout", func(t *testing.T) error {
			c := socks0.Client(newMem(), "x:1", early(func(c *socks0.Config) { c.ReplyTimeout = time.Millisecond }))
			return c.HandshakeContext(context.Background())
		}, socks0.KindTimeout},
		{"closed", func(t *testing.T) error {
			c := socks0.Client(newMem(), "x:1", nil)
			c.Close()
			_, err := c.Write([]byte("x"))
			return err
		}, socks0.KindClosed},
		{"reply 05 not refused", func(t *testing.T) error {
			_, err := hsRun(t, newMem(append([]byte{5, 0}, reply(5, "0.0.0.0:0")...)), 0, nil, true, nil)
			return err
		}, socks0.KindReply},
		{"reply 06 not timeout", func(t *testing.T) error {
			_, err := hsRun(t, newMem(append([]byte{5, 0}, reply(6, "0.0.0.0:0")...)), 0, nil, true, nil)
			return err
		}, socks0.KindReply},
		{"custom auth rejection", func(t *testing.T) error {
			mc := newMem([]byte{5, 0x80, 1})
			c := socks0.Client(mc, "x:1", &socks0.Config{Mode: socks0.ModeSequential, Auth: interactive{0x80}})
			return c.HandshakeContext(context.Background())
		}, socks0.KindAuth},
		{"custom auth EOF", func(t *testing.T) error {
			mc := newMem([]byte{5, 0x80})
			mc.closeServer()
			c := socks0.Client(mc, "x:1", &socks0.Config{Mode: socks0.ModeSequential, Auth: interactive{0x80}})
			return c.HandshakeContext(context.Background())
		}, socks0.KindEOF},
	}
	for _, tt := range cases {
		err := tt.err(t)
		if k := socks0.KindOf(err); k != tt.want {
			t.Errorf("%s: KindOf(%v) = %q, want %q", tt.name, err, k, tt.want)
		}
	}
	if socks0.KindOf(nil) != "" {
		t.Error("KindOf(nil)")
	}
}

func TestVerifyResetAtEveryStage(t *testing.T) {
	rst := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	for _, mode := range modes {
		msgs := serverMsgs(true, "192.0.2.1:1")
		for k := 0; k < len(msgs); k++ {
			mc := newMem(msgs[:k])
			mc.rst = rst
			_, err := hsRun(t, mc, mode, upAuth, true, nil)
			if err == nil {
				t.Fatalf("%v k=%d: no error", mode, k)
			}
			if !errors.Is(err, syscall.ECONNRESET) || socks0.KindOf(err) != socks0.KindReset {
				t.Errorf("%v k=%d: %v kind %q", mode, k, err, socks0.KindOf(err))
			}
		}
	}
}

// A real TCP RST (SO_LINGER 0) in the middle of the handshake.
func TestVerifyTCPReset(t *testing.T) {
	for _, mode := range modes {
		addr := listen(t, func(c net.Conn) {
			c.Read(make([]byte, 512))
			c.Write([]byte{5, 0, 5}) // method + 1 reply byte
			time.Sleep(10 * time.Millisecond)
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		})
		d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode}}
		err := handshakeErr(t.Context(), d, "example.com:80")
		k := socks0.KindOf(err)
		if k != socks0.KindReset && k != socks0.KindEOF {
			t.Errorf("%v: %v kind %q", mode, err, k)
		}
		if he := handshakeErrOf(t, err); he.Stage != wire.StageReply {
			t.Errorf("%v: stage %q", mode, he.Stage)
		}
	}
}
