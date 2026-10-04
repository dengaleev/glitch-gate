package socks0_test

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func listen(t testing.TB, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { defer c.Close(); handle(c) })
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

// pipeDial is a ProxyDial returning a net.Pipe whose far end handle serves.
func pipeDial(t testing.TB, handle func(net.Conn)) func(context.Context, string, string) (net.Conn, error) {
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	return func(context.Context, string, string) (net.Conn, error) {
		c, s := net.Pipe()
		wg.Go(func() { defer s.Close(); handle(s) })
		return c, nil
	}
}

type proxy struct {
	method   *wire.Method // selected; nil selects the one offered
	status   uint8        // RFC 1929 status
	rep      wire.Reply
	bound    wire.Addr      // zero: 192.0.2.1:1080
	tail     []byte         // sent in the same write as the reply
	coalesce bool           // read the whole pipelined handshake, then reply in one write
	after    func(net.Conn) // runs after a successful reply; nil echoes
	got      chan request   // receives what the client sent, if non-nil
}

type request struct {
	methods    []wire.Method
	user, pass string
	target     wire.Addr
}

var defaultBound = mustAddr("192.0.2.1:1080")

func mustAddr(s string) wire.Addr {
	a, err := wire.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func (p proxy) serve(c net.Conn) {
	var (
		req request
		out []byte
		err error
	)
	flush := func() {
		if !p.coalesce {
			c.Write(out)
			out = out[:0]
		}
	}
	if req.methods, err = wire.ReadGreeting(c); err != nil {
		return
	}
	m := req.methods[0]
	if p.method != nil {
		m = *p.method
	}
	out = wire.AppendMethodSelection(out, m)
	if m != req.methods[0] {
		c.Write(out)
		return
	}
	flush()
	if m == wire.MethodUserPass {
		u, pw, err := wire.ReadUserPass(c)
		if err != nil {
			return
		}
		req.user, req.pass = string(u), string(pw)
		if out = wire.AppendUserPassStatus(out, p.status); p.status != 0 {
			c.Write(out)
			return
		}
		flush()
	}
	if _, req.target, err = wire.ReadRequest(c); err != nil {
		return
	}
	if p.got != nil {
		p.got <- req
	}
	out, _ = wire.AppendReply(out, p.rep, cmp.Or(p.bound, defaultBound))
	c.Write(append(out, p.tail...))
	switch {
	case p.rep != wire.ReplySucceeded:
	case p.after != nil:
		p.after(c)
	default:
		io.Copy(c, c)
	}
}

// scripted answers resp to the first bytes, then half-closes unless silent.
func scripted(resp []byte, silent bool) func(net.Conn) {
	return func(c net.Conn) {
		buf := make([]byte, 1024)
		if _, err := c.Read(buf); err != nil {
			return
		}
		c.Write(resp)
		if !silent {
			closeWrite(c)
		}
		io.Copy(io.Discard, c)
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}

type recConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
	reads  []int // bytes asked for by each Read
	nread  int   // bytes returned
	over   bool  // a Read asked past limit
	limit  int   // if non-zero
	dls    []time.Time
}

func (c *recConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.reads = append(c.reads, len(b))
	c.over = c.over || c.limit > 0 && c.nread+len(b) > c.limit
	c.nread += n
	c.mu.Unlock()
	return n, err
}

func (c *recConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func (c *recConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.dls = append(c.dls, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *recConn) snapshot() (writes [][]byte, reads []int, nread int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.reads, c.nread
}

func recDial(ch chan<- *recConn) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		rc := &recConn{Conn: c}
		ch <- rc
		return rc, nil
	}
}

// handshakeErr dials and, in ModeEarly, completes the handshake.
func handshakeErr(ctx context.Context, d *socks0.Dialer, target string) error {
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	if sc, ok := c.(*socks0.Conn); ok {
		return sc.HandshakeContext(ctx)
	}
	return nil
}

func handshakeErrOf(t *testing.T, err error) *socks0.HandshakeError {
	t.Helper()
	op, ok := err.(*net.OpError)
	if !ok || !strings.HasPrefix(op.Op, "socks ") {
		t.Fatalf("err = %#v; want *net.OpError{Op: socks …}", err)
	}
	he, ok := op.Err.(*socks0.HandshakeError)
	if !ok {
		t.Fatalf("OpError.Err = %#v; want *HandshakeError", op.Err)
	}
	return he
}

var modes = []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly}

var errTest = errors.New("test error")
