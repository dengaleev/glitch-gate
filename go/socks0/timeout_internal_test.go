package socks0

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Built-in dial: the default timeout is a conn deadline, not a ctx.
func TestDefaultHandshakeTimeoutDeadline(t *testing.T) {
	old := defaultHandshakeTimeout
	defaultHandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { defaultHandshakeTimeout = old })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()

	cancelable, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, mode := range []Mode{ModeSequential, ModePipelined, ModeEarly} {
		for _, ctx := range []context.Context{context.Background(), cancelable} {
			d := &Dialer{ProxyAddr: ln.Addr().String(), Config: &Config{Mode: mode}}
			start := time.Now()
			c, err := d.DialContext(ctx, "tcp", "example.com:80")
			if err == nil { // ModeEarly: the reply wait, after the first Write
				if _, err = c.Write([]byte("x")); err == nil {
					_, err = c.Read(make([]byte, 1))
				}
				c.Close()
			}
			if mode != ModeEarly && !errors.Is(err, context.DeadlineExceeded) || KindOf(err) != KindTimeout {
				t.Errorf("%v: %v (kind %s), want a timeout", mode, err, KindOf(err))
			}
			if el := time.Since(start); el > 3*time.Second {
				t.Errorf("%v: took %v", mode, el)
			}
		}
	}

	// A ctx deadline governs alone: it fires first and is the error.
	defaultHandshakeTimeout = time.Hour
	ctx, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	d := &Dialer{ProxyAddr: ln.Addr().String()}
	if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ctx deadline: %v", err)
	}
}

type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

func tarpitPipe(t *testing.T) net.Conn {
	t.Helper()
	cl, pr := net.Pipe()
	go func() {
		defer pr.Close()
		_, _ = io.Copy(io.Discard, pr)
	}()
	t.Cleanup(func() { cl.Close() })
	return cl
}

// A bare timer; a conn that cannot set deadlines is closed to unblock it.
func TestConnHandshakeTimeoutTimer(t *testing.T) {
	old := defaultHandshakeTimeout
	defaultHandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { defaultHandshakeTimeout = old })

	for _, mode := range []Mode{ModeSequential, ModePipelined} {
		for _, noDL := range []bool{false, true} {
			for _, op := range []string{"Read", "Write", "HandshakeContext"} {
				nc := tarpitPipe(t)
				if noDL {
					nc = noDeadlineConn{nc}
				}
				c := ClientAddr(nc, mustAddrT(t, "example.com:80"), &Config{Mode: mode})
				start := time.Now()
				var err error
				switch op {
				case "Read":
					_, err = c.Read(make([]byte, 1))
				case "Write":
					_, err = c.Write([]byte("x"))
				default:
					err = c.HandshakeContext(context.Background())
				}
				if !errors.Is(err, context.DeadlineExceeded) || KindOf(err) != KindTimeout {
					t.Errorf("%v noDL=%v %s: %v (kind %s)", mode, noDL, op, err, KindOf(err))
				}
				if el := time.Since(start); el > 3*time.Second {
					t.Errorf("%v noDL=%v %s: took %v", mode, noDL, op, el)
				}
				if _, err2 := c.Write([]byte("y")); !errors.Is(err2, context.DeadlineExceeded) {
					t.Errorf("%v noDL=%v %s: not sticky: %v", mode, noDL, op, err2)
				}
				c.Close()
			}
		}
	}

	// A deadline on the wrapped conn, earlier than HandshakeTimeout, wins.
	defaultHandshakeTimeout = time.Hour
	nc := tarpitPipe(t)
	_ = nc.SetDeadline(time.Now().Add(50 * time.Millisecond))
	c := ClientAddr(nc, mustAddrT(t, "example.com:80"), nil)
	done := make(chan error, 1)
	go func() { done <- c.HandshakeContext(context.Background()) }()
	select {
	case err := <-done:
		if errors.Is(err, context.DeadlineExceeded) || !isTimeout(err) {
			t.Errorf("wrapped conn's deadline: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wrapped conn's deadline was overridden")
	}
	c.Close()
}

func mustAddrT(t *testing.T, s string) wire.Addr {
	t.Helper()
	a, err := wire.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
