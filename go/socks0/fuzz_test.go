package socks0_test

// Each target checks socks0 against a model built on the wire parsers:
//
//	go test -run '^$' -fuzz '^FuzzHandshake$' -fuzztime 60s

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// handshakeModel returns the expected kind ("" for success), the replies' length and BND.
func handshakeModel(srv []byte, withAuth, eof bool) (socks0.Kind, int, wire.Addr) {
	trunc := socks0.KindTimeout
	if eof {
		trunc = socks0.KindEOF
	}
	offered := wire.MethodNoAuth
	if withAuth {
		offered = wire.MethodUserPass
	}
	m, n, err := wire.ParseMethodSelection(srv)
	switch {
	case errors.Is(err, wire.ErrIncomplete):
		return trunc, 0, wire.Addr{}
	case err != nil:
		return socks0.KindProtocol, 0, wire.Addr{}
	case m != offered:
		return socks0.KindMethod, 0, wire.Addr{}
	}
	off := n
	if withAuth {
		st, n, err := wire.ParseUserPassStatus(srv[off:])
		switch {
		case errors.Is(err, wire.ErrIncomplete):
			return trunc, 0, wire.Addr{}
		case err != nil:
			return socks0.KindProtocol, 0, wire.Addr{}
		case st != 0:
			return socks0.KindAuth, 0, wire.Addr{}
		}
		off += n
	}
	rest := srv[off:]
	rep, bound, n, err := wire.ParseReply(rest, wire.CmdConnect)
	switch {
	case len(rest) > 1 && rest[0] == wire.Version5 && rep != wire.ReplySucceeded:
		return socks0.KindReply, 0, wire.Addr{}
	case errors.Is(err, wire.ErrIncomplete):
		return trunc, 0, wire.Addr{}
	case err != nil:
		return socks0.KindProtocol, 0, wire.Addr{}
	}
	return "", off + n, bound
}

// The client's handshake over any server bytes, split at any size, through a Client or a Dialer.
func FuzzHandshake(f *testing.F) {
	f.Add([]byte{0, 0}, append([]byte{5, 0}, reply(0, "192.0.2.1:1")...))
	f.Add([]byte{4, 1}, append([]byte{5, 2, 1, 0}, reply(0, "b.example:7")...))
	f.Add([]byte{2 | 8, 3}, append([]byte{5, 0}, reply(0, "[2001:db8::1]:2")...))
	f.Add([]byte{1 | 16, 0}, []byte{5, 0, 5, 5, 0, 3, 0})
	f.Add([]byte{2 | 32, 2}, append(append([]byte{5, 0}, reply(0, "x:1")...), "tail"...))
	f.Add([]byte{16, 0}, []byte("HTTP/1.1 200 OK"))
	f.Add([]byte{4 | 16, 1}, []byte{5, 2, 5, 1})
	f.Fuzz(func(t *testing.T, ctl, srv []byte) {
		if len(ctl) < 2 || len(srv) > 2048 {
			return
		}
		mode := socks0.Mode(ctl[0] % 3)
		withAuth, viaDialer, eof, earlyWrite := ctl[0]&4 != 0, ctl[0]&8 != 0, ctl[0]&16 != 0, ctl[0]&32 != 0
		var auth socks0.Authenticator
		if withAuth {
			auth = socks0.UserPass{Username: "u", Password: "FUZZPASSWORD"}
		}
		wantKind, wantLen, wantBound := handshakeModel(srv, withAuth, eof)

		mc := newMem(srv)
		mc.chunk = int(ctl[1] % 16)
		if eof {
			mc.closeServer()
		}
		cfg := &socks0.Config{Mode: mode, Auth: auth}
		// Short only where a timeout is expected: under fuzzing load it can beat present data.
		dl := 3 * time.Second
		if wantKind == socks0.KindTimeout {
			dl = 5 * time.Millisecond
		}
		type result struct {
			c   net.Conn
			err error
		}
		done := make(chan result, 1)
		go func() {
			var r result
			if viaDialer {
				ctx, cancel := context.WithTimeout(context.Background(), dl)
				defer cancel()
				d := &socks0.Dialer{ProxyAddr: "p:1", Config: cfg, ProxyDial: memDial(mc)}
				r.c, r.err = d.DialContext(ctx, "tcp", "example.com:80")
				if sc, ok := r.c.(*socks0.Conn); ok && r.err == nil {
					sc.SetDeadline(time.Now().Add(dl))
					if earlyWrite {
						sc.Write([]byte("early"))
					}
					r.err = sc.HandshakeContext(context.Background())
				}
			} else {
				c := socks0.Client(mc, "example.com:80", cfg)
				c.SetDeadline(time.Now().Add(dl))
				if earlyWrite {
					c.Write([]byte("early"))
				}
				r.c, r.err = c, c.HandshakeContext(context.Background())
			}
			done <- r
		}()
		var r result
		select {
		case r = <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("hang: mode %v auth %v dialer %v eof %v srv % x", mode, withAuth, viaDialer, eof, srv)
		}
		if got := socks0.KindOf(r.err); got != wantKind {
			t.Fatalf("mode %v auth %v dialer %v eof %v chunk %d srv % x: kind %q (%v), model %q",
				mode, withAuth, viaDialer, eof, mc.chunk, srv, got, r.err, wantKind)
		}
		if r.err != nil && strings.Contains(r.err.Error(), "FUZZPASSWORD") {
			t.Fatalf("password in %v", r.err)
		}
		raw := viaDialer && mode != socks0.ModeEarly
		if r.err != nil {
			if raw && (r.c != nil || mc.closes.Load() != 1) {
				t.Fatalf("failed dial: conn %v, closes %d", r.c, mc.closes.Load())
			}
			if !raw && mc.closes.Load() != 0 {
				t.Fatalf("Conn closed its conn on a handshake error")
			}
			if r.c != nil {
				r.c.Close()
			}
			return
		}
		if consumed, _, asks := mc.stats(); consumed != wantLen {
			t.Fatalf("consumed %d, replies are %d (asks %v) srv % x", consumed, wantLen, asks, srv)
		}
		if sc, ok := r.c.(*socks0.Conn); ok && sc.BoundAddr() != wantBound {
			t.Fatalf("BoundAddr %v, want %v", sc.BoundAddr(), wantBound)
		}
		if raw && r.c != net.Conn(mc) {
			t.Fatalf("L0/L1 Dialer returned %T", r.c)
		}
		// The bytes after the replies come through intact.
		if tail := srv[wantLen:]; len(tail) > 0 {
			r.c.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, len(tail))
			if _, err := io.ReadFull(r.c, b); err != nil || !bytes.Equal(b, tail) {
				t.Fatalf("tail %q, %v; want %q", b, err, tail)
			}
		}
		if earlyWrite && mode == socks0.ModeEarly && !bytes.HasSuffix(mc.written(), []byte("early")) {
			t.Fatalf("wrote % x", mc.written())
		}
		r.c.Close()
	})
}

// An accepted URL has an address; an error never holds the password.
func FuzzParseProxyURL(f *testing.F) {
	for _, s := range []string{"socks5://u:secretpw@h:1", "socks5h://[::1]:9050", "socks5s://h", "x://u:pw@", "socks5://u:longsecret@h:0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		p, err := socks0.ParseProxyURL(u)
		if err == nil {
			if p.Addr == "" {
				t.Fatalf("%q: empty Addr", raw)
			}
			return
		}
		if u.User != nil {
			if pw, ok := u.User.Password(); ok && len(pw) >= 6 && !strings.Contains(u.Redacted(), pw) && strings.Contains(err.Error(), pw) {
				t.Fatalf("%q: error leaks the password: %v", raw, err)
			}
		}
	})
}

// dgramConn: each Read returns the next queued datagram, truncated as UDP; then EOF.
type dgramConn struct {
	mu sync.Mutex
	q  [][]byte
}

func (c *dgramConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.q) == 0 {
		return 0, io.EOF
	}
	d := c.q[0]
	c.q = c.q[1:]
	return copy(b, d), nil
}
func (c *dgramConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *dgramConn) Close() error                     { return nil }
func (c *dgramConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *dgramConn) RemoteAddr() net.Addr             { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (c *dgramConn) SetDeadline(time.Time) error      { return nil }
func (c *dgramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dgramConn) SetWriteDeadline(time.Time) error { return nil }

// A datagram from the relay is delivered as the model says, or skipped.
func FuzzUDPRead(f *testing.F) {
	h4, _ := wire.AppendUDPHeader(nil, 0, mustAddr("192.0.2.1:53"))
	f.Add(append(h4, "payload"...), byte(0), 16)
	f.Add([]byte{0, 0, 1, 1, 192, 0, 2, 1, 0, 53, 'x'}, byte(1), 4)
	f.Add([]byte{0, 0, 0, 3, 3, 'a', '.', 'b', 0, 53, 'x'}, byte(2), 0)
	f.Add([]byte{0, 0, 0, 4}, byte(0), 300)
	f.Fuzz(func(t *testing.T, d []byte, kind byte, blen int) {
		blen = max(min(blen, 70000), 0)
		var target wire.Addr
		switch kind % 3 {
		case 1:
			target = mustAddr("192.0.2.1:53")
		case 2:
			target = mustAddr("a.b:53")
		}
		sentinelFrom := target
		if !target.IsValid() || target.IsName() {
			sentinelFrom = mustAddr("192.0.2.1:53")
		}
		sentinel := append(must(wire.AppendUDPHeader(nil, 0, sentinelFrom)), "SENTINEL"...)
		cc, cs := net.Pipe()
		defer cs.Close()
		u := socks0.NewUDPConn(cc, &dgramConn{q: [][]byte{bytes.Clone(d), sentinel}}, target)
		defer u.Close()
		b := make([]byte, blen)
		n, from, err := u.ReadFromAddr(b)
		if err != nil {
			t.Fatalf("ReadFromAddr: %v", err)
		}
		if n > len(b) || n < 0 {
			t.Fatalf("n = %d of %d", n, len(b))
		}
		// The relay read buffer is len(b)+262 (capped): truncation precedes parsing.
		d = d[:min(len(d), blen+wire.MaxUDPHeaderLen, 65535)]
		frag, src, hn, perr := wire.ParseUDPHeader(d)
		want := []byte("SENTINEL")
		if perr == nil && frag == 0 && (!target.IsValid() || target.IsName() || src == target) {
			want = d[hn:]
			if from != src {
				t.Fatalf("from %v; want %v", from, src)
			}
		}
		if want = want[:min(len(want), len(b))]; !bytes.Equal(b[:n], want) {
			t.Fatalf("got %q; want %q", b[:n], want)
		}
	})
}

// Listen and Accept over any server bytes, SOCKS5 or SOCKS4, agree with the reply parsers.
func FuzzListen(f *testing.F) {
	r1, _ := wire.AppendReply(nil, 0, mustAddr("0.0.0.0:21"))
	r2, _ := wire.AppendReply(nil, 0, mustAddr("192.0.2.1:2000"))
	f.Add(append(append(append([]byte{5, 0}, r1...), r2...), "data"...), false, byte(1))
	q1, _ := wire.AppendReply4(nil, wire.Reply4Granted, mustAddr("0.0.0.0:21"))
	q2, _ := wire.AppendReply4(nil, wire.Reply4Granted, mustAddr("192.0.2.1:2000"))
	f.Add(append(append(q1, q2...), "data"...), true, byte(0))
	f.Add([]byte{5, 0, 5, 0, 0, 3, 0, 0, 21}, false, byte(2))
	f.Fuzz(func(t *testing.T, srv []byte, v4 bool, mode byte) {
		mc := newMem(srv)
		mc.closeServer()
		cfg := &socks0.Config{Mode: socks0.Mode(mode % 3)}
		if v4 {
			cfg.Version = 4
		}
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080", Config: cfg, ProxyDial: memDial(mc)}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ln, err := d.Listen(ctx, "tcp", "192.0.2.9:0")

		var n1, n2 int
		var ok1, ok2 bool
		if v4 {
			rep, bound, n, err := wire.ParseReply4(srv)
			ok1, n1 = err == nil && rep == wire.Reply4Granted && bound.Port() != 0, n
			if ok1 {
				rep, _, n, err := wire.ParseReply4(srv[n1:])
				ok2, n2 = err == nil && rep == wire.Reply4Granted, n
			}
		} else if len(srv) >= 2 && srv[0] == 5 && srv[1] == 0 {
			rep, bound, n, err := wire.ParseReply(srv[2:], wire.CmdBind)
			ok1, n1 = err == nil && rep == 0 && bound.Port() != 0, 2+n
			if ok1 {
				rep, _, n, err := wire.ParseReply(srv[n1:], wire.CmdBind)
				ok2, n2 = err == nil && rep == 0, n
			}
		}
		if (err == nil) != ok1 {
			t.Fatalf("Listen = %v; model ok=%v", err, ok1)
		}
		if err != nil {
			if k := socks0.KindOf(err); k == "" || k == socks0.KindOther {
				t.Fatalf("Listen kind %q: %v", k, err)
			}
			return
		}
		if consumed, _, _ := mc.stats(); consumed != n1 {
			t.Fatalf("Listen consumed %d, reply 1 ends at %d", consumed, n1)
		}
		c, err := ln.Accept()
		if (err == nil) != ok2 {
			t.Fatalf("Accept = %v; model ok=%v", err, ok2)
		}
		if err != nil {
			if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageAccept {
				t.Fatalf("Accept err %v", err)
			}
			return
		}
		if rest, _ := io.ReadAll(c); !bytes.Equal(rest, srv[n1+n2:]) {
			t.Fatalf("accepted conn read %q, want %q", rest, srv[n1+n2:])
		}
	})
}

// A Tor RESOLVE or RESOLVE_PTR over any server bytes yields one answer or a *net.DNSError, and closes its conn.
func FuzzLookup(f *testing.F) {
	f.Add([]byte{5, 0, 5, 0, 0, 1, 192, 0, 2, 1, 0, 0}, false)
	f.Add([]byte{5, 0, 5, 4, 0, 0, 0, 0, 0, 0, 0, 0}, true)
	f.Add([]byte{5, 0, 5, 0, 0, 3, 3, 'a', '.', 'b', 0, 0}, true)
	f.Fuzz(func(t *testing.T, srv []byte, ptr bool) {
		mc := newMem(srv)
		mc.closeServer()
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:9050", ProxyDial: memDial(mc)}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var err error
		if ptr {
			var names []string
			if names, err = d.LookupAddr(ctx, "2001:db8::1"); err == nil && (len(names) != 1 || names[0] == "") {
				t.Fatalf("names %q", names)
			}
		} else {
			var ips []netip.Addr
			if ips, err = d.LookupNetIP(ctx, "ip", "example.com"); err == nil && (len(ips) != 1 || !ips[0].IsValid() || ips[0].Is4In6()) {
				t.Fatalf("ips %v", ips)
			}
		}
		if _, ok := err.(*net.DNSError); err != nil && !ok {
			t.Fatalf("err %T %v", err, err)
		}
		if mc.closes.Load() == 0 {
			t.Fatal("conn not closed")
		}
	})
}
