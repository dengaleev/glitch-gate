package socks0_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// bind5 serves the SOCKS5 front of a BIND (no auth), then script.
func bind5(t *testing.T, script func(c net.Conn)) string {
	return listen(t, func(c net.Conn) {
		if _, err := wire.ReadGreeting(c); err != nil {
			return
		}
		c.Write(wire.AppendMethodSelection(nil, wire.MethodNoAuth))
		if cmd, _, err := wire.ReadRequest(c); err != nil || cmd != wire.CmdBind {
			return
		}
		script(c)
	})
}

type bindLog struct {
	mu       sync.Mutex
	replies  int
	accepted []string
	peer     wire.Addr
}

func (l *bindLog) trace() *socks0.ClientTrace {
	return &socks0.ClientTrace{
		GotReply: func(wire.Reply, wire.Addr) { l.mu.Lock(); l.replies++; l.mu.Unlock() },
		Accepted: func(peer wire.Addr, err error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.peer = peer
			if err != nil {
				l.accepted = append(l.accepted, err.Error())
			} else {
				l.accepted = append(l.accepted, "ok")
			}
		},
	}
}

func TestV2BindEOFBeforeReply2(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var log bindLog
			addr := bind5(t, func(c net.Conn) {
				c.Write(reply(0, "127.0.0.1:5555"))
				// close without reply 2
			})
			d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode, Trace: log.trace()}}
			ln, err := d.Listen(t.Context(), "tcp", "192.0.2.1:21")
			if err != nil {
				t.Fatal(err)
			}
			_, err = ln.Accept()
			oe, ok := err.(*net.OpError)
			if !ok || oe.Op != "socks bind" {
				t.Fatalf("Accept = %#v", err)
			}
			he, ok := oe.Err.(*socks0.HandshakeError)
			if !ok || he.Stage != socks0.StageAccept {
				t.Fatalf("Accept err = %#v", oe.Err)
			}
			pe, ok := he.Err.(*socks0.ProtocolError)
			if !ok || pe.Stage != wire.StageReply || !errors.Is(pe.Err, io.ErrUnexpectedEOF) {
				t.Errorf("cause = %#v", he.Err)
			}
			if socks0.KindOf(err) != socks0.KindEOF {
				t.Errorf("KindOf = %q", socks0.KindOf(err))
			}
			log.mu.Lock()
			if log.replies != 1 || len(log.accepted) != 1 || log.accepted[0] == "ok" {
				t.Errorf("trace: replies %d, accepted %q", log.replies, log.accepted)
			}
			log.mu.Unlock()
			if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("2nd Accept = %v", err)
			}
			if err := ln.Close(); err != nil {
				t.Errorf("Close after failed Accept = %v", err)
			}
		})
	}
}

// Listen must leave reply 2 and the peer's data unread.
func TestV2BindCoalesced(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var log bindLog
			addr := bind5(t, func(c net.Conn) {
				b := reply(0, "0.0.0.0:5555")
				b = append(b, reply(0, "[2001:db8::7]:4444")...)
				b = append(b, "peer-data"...)
				c.Write(b)
				io.Copy(io.Discard, c)
			})
			d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode, Trace: log.trace()}}
			ln, err := d.Listen(t.Context(), "tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			l := ln.(*socks0.Listener)
			if a, ok := l.Addr().(*net.TCPAddr); !ok || a.String() != "127.0.0.1:5555" {
				t.Errorf("Addr = %#v", l.Addr())
			}
			if l.BoundAddr().String() != "0.0.0.0:5555" {
				t.Errorf("BoundAddr = %v", l.BoundAddr())
			}
			time.Sleep(20 * time.Millisecond)
			c, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.RemoteAddr().String() != "[2001:db8::7]:4444" || c.LocalAddr().String() != "127.0.0.1:5555" {
				t.Errorf("addrs %v %v", c.LocalAddr(), c.RemoteAddr())
			}
			if b := c.(*socks0.Conn).BoundAddr(); b.String() != "[2001:db8::7]:4444" {
				t.Errorf("BoundAddr = %v", b)
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 100)
			n, err := io.ReadAtLeast(c, buf, len("peer-data"))
			if err != nil || string(buf[:n]) != "peer-data" {
				t.Errorf("Read = %q %v", buf[:n], err)
			}
			log.mu.Lock()
			if log.replies != 1 || len(log.accepted) != 1 || log.accepted[0] != "ok" || log.peer.String() != "[2001:db8::7]:4444" {
				t.Errorf("trace: replies %d accepted %q peer %v", log.replies, log.accepted, log.peer)
			}
			log.mu.Unlock()
			// Close after Accept: no-op, the conn survives
			if err := ln.Close(); err != nil {
				t.Errorf("Close = %v", err)
			}
			if _, err := c.Write([]byte("x")); err != nil {
				t.Errorf("Write after ln.Close = %v", err)
			}
			if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("2nd Accept = %v", err)
			}
		})
	}
}

func TestV2BindCtxAfterListen(t *testing.T) {
	release := make(chan struct{})
	addr := bind5(t, func(c net.Conn) {
		c.Write(reply(0, "127.0.0.1:5555"))
		<-release
		c.Write(append(reply(0, "192.0.2.9:1"), "hi"...))
		io.Copy(io.Discard, c)
	})
	ctx, cancel := context.WithCancel(t.Context())
	d := &socks0.Dialer{ProxyAddr: addr}
	ln, err := d.Listen(ctx, "tcp", "192.0.2.9:0")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	close(release)
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept after ctx cancel = %v", err)
	}
	c.Close()
}

func TestV2BindCtxDuringListen(t *testing.T) {
	addr := bind5(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	base := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(30*time.Millisecond, cancel)
	d := &socks0.Dialer{ProxyAddr: addr}
	_, err := d.Listen(ctx, "tcp", "192.0.2.9:0")
	if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled {
		t.Fatalf("Listen = %v (%q)", err, socks0.KindOf(err))
	}
	if he := handshakeErrOf(t, err); he.Stage != wire.StageReply {
		t.Errorf("stage %q", he.Stage)
	}
	waitGoroutines(t, base+1)
}

func TestV2BindCloseDuringAccept(t *testing.T) {
	var log bindLog
	addr := bind5(t, func(c net.Conn) {
		c.Write(reply(0, "127.0.0.1:5555"))
		io.Copy(io.Discard, c)
	})
	d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Trace: log.trace()}}
	ln, err := d.Listen(t.Context(), "tcp", "192.0.2.9:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 2)
	for range 2 {
		go func() { _, err := ln.Accept(); errc <- err }()
	}
	time.Sleep(30 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	for range 2 {
		select {
		case err := <-errc:
			if !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
				t.Errorf("Accept = %v (%q)", err, socks0.KindOf(err))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Accept not unblocked by Close")
		}
	}
	if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("2nd Close = %v", err)
	}
	log.mu.Lock()
	if len(log.accepted) != 1 {
		t.Errorf("Accepted ran %d times", len(log.accepted))
	}
	log.mu.Unlock()
}

func TestV2BindReply2Failure(t *testing.T) {
	addr := bind5(t, func(c net.Conn) {
		c.Write(reply(0, "127.0.0.1:5555"))
		c.Write(reply(wire.ReplyNotAllowed, "0.0.0.0:0"))
	})
	d := &socks0.Dialer{ProxyAddr: addr}
	ln, err := d.Listen(t.Context(), "tcp", "192.0.2.9:0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ln.Accept()
	re, ok := errors.AsType[*socks0.ReplyError](err)
	if !ok || re.Reply != wire.ReplyNotAllowed || socks0.KindOf(err) != socks0.KindReply {
		t.Fatalf("Accept = %v", err)
	}
	if he := handshakeErrOf(t, err); he.Stage != socks0.StageAccept {
		t.Errorf("stage %q", he.Stage)
	}
	if err.(*net.OpError).Op != "socks bind" {
		t.Errorf("op %q", err.(*net.OpError).Op)
	}
}

func TestV2BindDeadline(t *testing.T) {
	addr := bind5(t, func(c net.Conn) {
		c.Write(reply(0, "127.0.0.1:5555"))
		io.Copy(io.Discard, c)
	})
	d := &socks0.Dialer{ProxyAddr: addr}
	ln, err := d.Listen(t.Context(), "tcp", "192.0.2.9:0")
	if err != nil {
		t.Fatal(err)
	}
	l := ln.(*socks0.Listener)
	l.SetDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	_, err = ln.Accept()
	if !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || time.Since(start) > time.Second {
		t.Errorf("Accept = %v (%q)", err, socks0.KindOf(err))
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Errorf("not a net.Error timeout: %#v", err)
	}
	if err := l.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetDeadline after Accept = %v", err)
	}
}

func TestV2Bind4EOF(t *testing.T) {
	addr := listen(t, func(c net.Conn) {
		if _, _, _, err := wire.ReadRequest4(c); err != nil {
			return
		}
		b, _ := wire.AppendReply4(nil, wire.Reply4Granted, mustAddr("0.0.0.0:5555"))
		c.Write(b)
	})
	d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Version: 4}}
	ln, err := d.Listen(t.Context(), "tcp", "192.0.2.9:0")
	if err != nil {
		t.Fatal(err)
	}
	if ln.Addr().String() != "127.0.0.1:5555" {
		t.Errorf("Addr = %v", ln.Addr())
	}
	_, err = ln.Accept()
	pe, ok := errors.AsType[*socks0.ProtocolError](err)
	if !ok || pe.Stage != wire.StageReply4 || socks0.KindOf(err) != socks0.KindEOF {
		t.Errorf("Accept = %v", err)
	}
	// SOCKS4 has no "unknown" DST
	if _, err := d.Listen(t.Context(), "tcp", ""); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("SOCKS4 Listen(\"\") = %v", err)
	}
}
