package socks0_test

// Differential fuzzing against a model built on the wire parsers:
//
//	go test -run '^$' -fuzz FuzzVerifyClientScript -fuzztime 60s

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// model returns the expected kind ("" for success), the replies' length and BND.
func model(srv []byte, withAuth, eof bool) (socks0.Kind, int, wire.Addr) {
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

func FuzzVerifyClientScript(f *testing.F) {
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
		withAuth := ctl[0]&4 != 0
		viaDialer := ctl[0]&8 != 0
		eof := ctl[0]&16 != 0
		earlyWrite := ctl[0]&32 != 0
		var auth socks0.Authenticator
		if withAuth {
			auth = socks0.UserPass{Username: "u", Password: "FUZZPASSWORD"}
		}
		wantKind, wantLen, wantBound := model(srv, withAuth, eof)

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
				d := &socks0.Dialer{ProxyAddr: "p:1", Config: cfg,
					ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
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
		got := socks0.KindOf(r.err)
		if got != wantKind {
			t.Fatalf("mode %v auth %v dialer %v eof %v chunk %d srv % x: kind %q (%v), model %q",
				mode, withAuth, viaDialer, eof, mc.chunk, srv, got, r.err, wantKind)
		}
		if r.err != nil && bytes.Contains([]byte(r.err.Error()), []byte("FUZZPASSWORD")) {
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
		consumed, _, _, asks := mc.stats()
		if consumed != wantLen {
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
		if earlyWrite && mode == socks0.ModeEarly {
			if w := mc.written(); !bytes.HasSuffix(w, []byte("early")) {
				t.Fatalf("wrote % x", w)
			}
		}
		r.c.Close()
	})
}
