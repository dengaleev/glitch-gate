package socks0_test

//
//	go test -run '^$' -fuzz FuzzV2UDPRead -fuzztime 60s
//	go test -run '^$' -fuzz FuzzV2Bind -fuzztime 60s
//	go test -run '^$' -fuzz FuzzV2Resolve -fuzztime 60s

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

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

func FuzzV2UDPRead(f *testing.F) {
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
		sentinel, _ := wire.AppendUDPHeader(nil, 0, ipOr(target, mustAddr("192.0.2.1:53")))
		sentinel = append(sentinel, "SENTINEL"...)
		relay := &dgramConn{q: [][]byte{bytes.Clone(d), sentinel}}
		cc, cs := net.Pipe()
		defer cs.Close()
		var drops int
		u := socks0.NewUDPConn(cc, relay, target)
		defer u.Close()
		_ = drops
		b := make([]byte, blen)
		n, from, err := u.ReadFromAddr(b)
		if err != nil {
			t.Fatalf("ReadFromAddr: %v", err)
		}
		if n > len(b) || n < 0 {
			t.Fatalf("n = %d of %d", n, len(b))
		}
		frag, src, hn, perr := wire.ParseUDPHeader(d)
		accepted := perr == nil && frag == 0 && (!target.IsValid() || target.IsName() || src == target)
		// the relay read buffer is len(b)+262 (capped): truncation precedes parsing
		limit := min(blen+wire.MaxUDPHeaderLen, 65535)
		if len(d) > limit {
			frag, src, hn, perr = wire.ParseUDPHeader(d[:limit])
			accepted = perr == nil && frag == 0 && (!target.IsValid() || target.IsName() || src == target)
			d = d[:limit]
		}
		if accepted {
			want := d[hn:]
			if len(want) > len(b) {
				want = want[:len(b)]
			}
			if from != src || !bytes.Equal(b[:n], want) {
				t.Fatalf("got %q from %v; want %q from %v", b[:n], from, want, src)
			}
		} else {
			want := []byte("SENTINEL")
			if len(want) > len(b) {
				want = want[:len(b)]
			}
			if !bytes.Equal(b[:n], want) {
				t.Fatalf("dropped datagram not skipped: got %q", b[:n])
			}
		}
	})
}

func ipOr(a, b wire.Addr) wire.Addr {
	if a.IsValid() && !a.IsName() {
		return a
	}
	return b
}

func FuzzV2Bind(f *testing.F) {
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
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080", Config: cfg,
			ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ln, err := d.Listen(ctx, "tcp", "192.0.2.9:0")

		var n1, n2 int
		var ok1, ok2 bool
		if v4 {
			rep, _, n, err := wire.ParseReply4(srv)
			bound := wire.Addr{}
			if err == nil {
				_, bound, _, _ = wire.ParseReply4(srv)
			}
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
			if socks0.KindOf(err) == "" || socks0.KindOf(err) == socks0.KindOther {
				t.Fatalf("Listen kind %q: %v", socks0.KindOf(err), err)
			}
			return
		}
		if consumed, _, _, _ := mc.stats(); consumed != n1 {
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
		rest, _ := io.ReadAll(c)
		if !bytes.Equal(rest, srv[n1+n2:]) {
			t.Fatalf("accepted conn read %q, want %q", rest, srv[n1+n2:])
		}
	})
}

func FuzzV2Resolve(f *testing.F) {
	f.Add([]byte{5, 0, 5, 0, 0, 1, 192, 0, 2, 1, 0, 0}, false)
	f.Add([]byte{5, 0, 5, 4, 0, 0, 0, 0, 0, 0, 0, 0}, true)
	f.Add([]byte{5, 0, 5, 0, 0, 3, 3, 'a', '.', 'b', 0, 0}, true)
	f.Fuzz(func(t *testing.T, srv []byte, ptr bool) {
		mc := newMem(srv)
		mc.closeServer()
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:9050",
			ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var err error
		if ptr {
			var names []string
			names, err = d.LookupAddr(ctx, "2001:db8::1")
			if err == nil && (len(names) != 1 || names[0] == "") {
				t.Fatalf("names %q", names)
			}
		} else {
			var ips []netip.Addr
			ips, err = d.LookupNetIP(ctx, "ip", "example.com")
			if err == nil && (len(ips) != 1 || !ips[0].IsValid() || ips[0].Is4In6()) {
				t.Fatalf("ips %v", ips)
			}
		}
		if err != nil {
			if _, ok := err.(*net.DNSError); !ok {
				t.Fatalf("err %T %v", err, err)
			}
		}
		if mc.closes.Load() == 0 {
			t.Fatal("conn not closed")
		}
	})
}
