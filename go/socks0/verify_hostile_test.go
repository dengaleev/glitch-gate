package socks0_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// hsRun returns the data conn: an L0/L1 Dialer's raw conn, else the *Conn.
func hsRun(t testing.TB, mc *memConn, mode socks0.Mode, auth socks0.Authenticator, viaDialer bool, trace *socks0.ClientTrace) (net.Conn, error) {
	t.Helper()
	cfg := &socks0.Config{Mode: mode, Auth: auth, Trace: trace}
	if !viaDialer {
		c := socks0.Client(mc, "example.com:80", cfg)
		return c, c.HandshakeContext(context.Background())
	}
	d := &socks0.Dialer{ProxyAddr: "proxy.example:1080", Config: cfg,
		ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		return nil, err
	}
	if sc, ok := c.(*socks0.Conn); ok {
		return c, sc.HandshakeContext(context.Background())
	}
	return c, nil
}

var upAuth = socks0.UserPass{Username: "user", Password: "S3CRETpw"}

func serverMsgs(auth bool, bound string) []byte {
	b := []byte{5, 0}
	if auth {
		b = []byte{5, 2, 1, 0}
	}
	return append(b, reply(0, bound)...)
}

var bounds = []string{"192.0.2.1:1080", "[2001:db8::1]:443", "b.example:7", "x:1", "0.0.0.0:0"}

func TestVerifyExactReadAllChunkings(t *testing.T) {
	tail := []byte("TUNNEL-DATA-0123456789")
	for _, mode := range modes {
		for _, withAuth := range []bool{false, true} {
			for _, bound := range bounds {
				msgs := serverMsgs(withAuth, bound)
				for chunk := 1; chunk <= len(msgs)+len(tail); chunk++ {
					for _, viaDialer := range []bool{false, true} {
						name := fmt.Sprintf("%v/auth=%v/%s/chunk=%d/dialer=%v", mode, withAuth, bound, chunk, viaDialer)
						mc := newMem(msgs, tail)
						mc.chunk = chunk
						var auth socks0.Authenticator
						if withAuth {
							auth = upAuth
						}
						var gotBound wire.Addr
						tr := &socks0.ClientTrace{GotReply: func(_ wire.Reply, b wire.Addr) { gotBound = b }}
						c, err := hsRun(t, mc, mode, auth, viaDialer, tr)
						if err != nil {
							t.Fatalf("%s: %v", name, err)
						}
						consumed, _, _, asks := mc.stats()
						if consumed != len(msgs) {
							t.Errorf("%s: consumed %d bytes, replies are %d (asks %v)", name, consumed, len(msgs), asks)
						}
						if gotBound != mustAddr(bound) {
							t.Errorf("%s: GotReply bound %v", name, gotBound)
						}
						if sc, ok := c.(*socks0.Conn); ok && sc.BoundAddr() != mustAddr(bound) {
							t.Errorf("%s: BoundAddr %v", name, sc.BoundAddr())
						}
						got := make([]byte, len(tail))
						if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, tail) {
							t.Errorf("%s: tail %q, %v", name, got, err)
						}
						c.Close()
					}
				}
			}
		}
	}
}

func TestVerifyExactReadEverySplit(t *testing.T) {
	tail := []byte("tail!")
	for _, mode := range modes {
		for _, withAuth := range []bool{false, true} {
			for _, bound := range bounds {
				msgs := serverMsgs(withAuth, bound)
				for k := 1; k < len(msgs); k++ {
					mc := newMem(msgs[:k])
					var auth socks0.Authenticator
					if withAuth {
						auth = upAuth
					}
					time.AfterFunc(time.Millisecond, func() { mc.feed(append(slices.Clip(msgs[k:]), tail...)) })
					c, err := hsRun(t, mc, mode, auth, false, nil)
					if err != nil {
						t.Fatalf("%v k=%d: %v", mode, k, err)
					}
					if consumed, _, _, asks := mc.stats(); consumed != len(msgs) {
						t.Errorf("%v auth=%v %s k=%d: consumed %d of %d (asks %v)", mode, withAuth, bound, k, consumed, len(msgs), asks)
					}
					got := make([]byte, len(tail))
					if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, tail) {
						t.Errorf("tail %q, %v", got, err)
					}
					c.Close()
				}
			}
		}
	}
}

func TestVerifySlowloris(t *testing.T) {
	msgs := serverMsgs(true, "[2001:db8::1]:443")
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			mc := newMem()
			go func() {
				for _, b := range append(slices.Clip(msgs), "tail"...) {
					time.Sleep(100 * time.Millisecond)
					mc.feed([]byte{b})
				}
			}()
			c, err := hsRun(t, mc, mode, upAuth, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if consumed, _, _, _ := mc.stats(); consumed != len(msgs) {
				t.Errorf("consumed %d of %d", consumed, len(msgs))
			}
			got := make([]byte, 4)
			io.ReadFull(c, got)
			if string(got) != "tail" {
				t.Errorf("tail %q", got)
			}
			c.Close()
		})
		t.Run(mode.String()+"/deadline", func(t *testing.T) {
			t.Parallel()
			mc := newMem()
			go func() {
				for _, b := range msgs[:5] { // method, auth status, first reply byte
					time.Sleep(10 * time.Millisecond)
					mc.feed([]byte{b})
				}
			}()
			c := socks0.Client(mc, "example.com:80", &socks0.Config{Mode: mode, Auth: upAuth})
			c.SetDeadline(time.Now().Add(150 * time.Millisecond))
			err := c.HandshakeContext(context.Background())
			he := handshakeErrOf(t, err)
			if he.Stage != wire.StageReply || !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout {
				t.Errorf("err %v stage %q kind %q", err, he.Stage, socks0.KindOf(err))
			}
		})
	}
}

func TestVerifyServerClosesAtEveryStage(t *testing.T) {
	for _, mode := range modes {
		for _, withAuth := range []bool{false, true} {
			msgs := serverMsgs(withAuth, "b.example:7")
			for k := 0; k < len(msgs); k++ {
				for _, viaDialer := range []bool{false, true} {
					mc := newMem(msgs[:k])
					mc.closeServer()
					var auth socks0.Authenticator
					if withAuth {
						auth = upAuth
					}
					_, err := hsRun(t, mc, mode, auth, viaDialer, nil)
					name := fmt.Sprintf("%v auth=%v k=%d dialer=%v", mode, withAuth, k, viaDialer)
					if err == nil {
						t.Fatalf("%s: no error", name)
					}
					he := handshakeErrOf(t, err)
					m := 2
					want := wire.StageMethodSelection
					if withAuth && k >= 2 {
						want, m = wire.StageUserPassStatus, 4
					}
					if k >= m {
						want = wire.StageReply
					}
					if he.Stage != want || socks0.KindOf(err) != socks0.KindEOF || !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Errorf("%s: %v (stage %q kind %q)", name, err, he.Stage, socks0.KindOf(err))
					}
					if viaDialer && mode != socks0.ModeEarly && mc.closes.Load() != 1 {
						t.Errorf("%s: conn closed %d times", name, mc.closes.Load())
					}
					if !viaDialer || mode == socks0.ModeEarly {
						if mc.closes.Load() != 0 {
							t.Errorf("%s: Conn closed the conn before Close", name)
						}
					}
				}
			}
		}
	}
}

// Prefilled: the server answers before reading anything.
func TestVerifyHostileReplies(t *testing.T) {
	huge := append([]byte{5, 0, 5, 0, 0, 3, 255}, bytes.Repeat([]byte{'a'}, 255)...)
	huge = append(huge, 0, 80)
	for _, tt := range []struct {
		name  string
		resp  []byte
		auth  bool
		stage string
		kind  socks0.Kind
		ok    bool
		field string
		hint  string
	}{
		{name: "0xFF", resp: []byte{5, 0xFF, 9, 9, 9}, stage: wire.StageMethodSelection, kind: socks0.KindMethod},
		{name: "unoffered", resp: []byte{5, 0x03, 9, 9}, stage: wire.StageMethodSelection, kind: socks0.KindMethod},
		{name: "unoffered noauth vs userpass", resp: []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, auth: true, stage: wire.StageMethodSelection, kind: socks0.KindMethod},
		{name: "auth status 1", resp: []byte{5, 2, 1, 1}, auth: true, stage: wire.StageUserPassStatus, kind: socks0.KindAuth},
		{name: "auth status 0xFF", resp: []byte{5, 2, 1, 0xFF}, auth: true, stage: wire.StageUserPassStatus, kind: socks0.KindAuth},
		{name: "auth VER 5 (Tor)", resp: []byte{5, 2, 5, 1}, auth: true, stage: wire.StageUserPassStatus, kind: socks0.KindProtocol, field: "VER", hint: "Tor"},
		{name: "auth VER 0", resp: []byte{5, 2, 0, 0}, auth: true, stage: wire.StageUserPassStatus, kind: socks0.KindProtocol, field: "VER", hint: "SOCKS4"},
		{name: "VER H", resp: []byte("HTTP/1.0 200 OK\r\n\r\n"), stage: wire.StageMethodSelection, kind: socks0.KindProtocol, field: "VER", hint: "HTTP"},
		{name: "VER 0", resp: []byte{0, 0x5a, 0, 0, 0, 0, 0, 0}, stage: wire.StageMethodSelection, kind: socks0.KindProtocol, field: "VER", hint: "SOCKS4"},
		{name: "VER 4", resp: []byte{4, 0}, stage: wire.StageMethodSelection, kind: socks0.KindProtocol, field: "VER"},
		{name: "reply VER H", resp: []byte("\x05\x00HTTP/1.1 400"), stage: wire.StageReply, kind: socks0.KindProtocol, field: "VER", hint: "HTTP"},
		{name: "reply VER 0", resp: []byte{5, 0, 0, 0x5a, 0, 0, 0, 0, 0, 0}, stage: wire.StageReply, kind: socks0.KindProtocol, field: "VER", hint: "SOCKS4"},
		{name: "ATYP 0 in CONNECT", resp: []byte{5, 0, 5, 0, 0, 0, 1, 2, 3, 4, 0, 80}, stage: wire.StageReply, kind: socks0.KindProtocol, field: "ATYP"},
		{name: "ATYP 2", resp: []byte{5, 0, 5, 0, 0, 2, 1, 2, 3, 4, 0, 80}, stage: wire.StageReply, kind: socks0.KindProtocol, field: "ATYP"},
		{name: "domain len 0", resp: []byte{5, 0, 5, 0, 0, 3, 0, 0, 80}, stage: wire.StageReply, kind: socks0.KindProtocol, field: "ADDR"},
		{name: "REP 1 ATYP 0", resp: []byte{5, 0, 5, 1, 0, 0, 1, 2, 3, 4, 0, 80}, stage: wire.StageReply, kind: socks0.KindReply},
		{name: "REP 5 domain len 0", resp: []byte{5, 0, 5, 5, 0, 3, 0}, stage: wire.StageReply, kind: socks0.KindReply},
		{name: "REP 0xFF garbage", resp: []byte{5, 0, 5, 0xFF, 0xFF, 0xFF, 0xFF}, stage: wire.StageReply, kind: socks0.KindReply},
		{name: "RSV nonzero ok", resp: []byte{5, 0, 5, 0, 0xEE, 1, 1, 2, 3, 4, 0, 80}, ok: true},
		{name: "huge domain BND ok", resp: huge, ok: true},
		{name: "IPv4-mapped IPv6 BND ok", resp: []byte{5, 0, 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4, 0, 80}, ok: true},
	} {
		for _, mode := range modes {
			for _, viaDialer := range []bool{false, true} {
				name := fmt.Sprintf("%s/%v/dialer=%v", tt.name, mode, viaDialer)
				mc := newMem(tt.resp, []byte("GARBAGE-AFTER"))
				mc.closeServer()
				var auth socks0.Authenticator
				if tt.auth {
					auth = upAuth
				}
				c, err := hsRun(t, mc, mode, auth, viaDialer, nil)
				if tt.ok {
					if err != nil {
						t.Errorf("%s: %v", name, err)
					} else {
						c.Close()
					}
					continue
				}
				if err == nil {
					t.Errorf("%s: no error", name)
					continue
				}
				he := handshakeErrOf(t, err)
				if he.Stage != tt.stage || socks0.KindOf(err) != tt.kind {
					t.Errorf("%s: %v (stage %q, kind %q)", name, err, he.Stage, socks0.KindOf(err))
				}
				if pe, ok := errors.AsType[*socks0.ProtocolError](err); ok {
					if pe.Field != tt.field || pe.Stage != he.Stage || (tt.hint != "" && !bytes.Contains([]byte(pe.Hint), []byte(tt.hint))) {
						t.Errorf("%s: ProtocolError %+v", name, pe)
					}
				} else if tt.field != "" {
					t.Errorf("%s: want a ProtocolError, got %v", name, err)
				}
				if bytes.Contains([]byte(err.Error()), []byte("S3CRET")) {
					t.Errorf("%s: password in error", name)
				}
			}
		}
	}
}

// A v4-mapped BND is unmapped; a domain BND "1.2.3.4" stays a name.
func TestVerifyBoundForms(t *testing.T) {
	mapped := []byte{5, 0, 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4, 0, 80}
	c, err := hsRun(t, newMem(mapped), socks0.ModePipelined, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.(*socks0.Conn).BoundAddr(); b.String() != "1.2.3.4:80" || b.ATYP() != wire.ATYPIPv4 {
		t.Errorf("mapped BND = %v (%v)", b, b.ATYP())
	}
	name := append([]byte{5, 0, 5, 0, 0, 3, 7}, "1.2.3.4\x00\x50"...)
	c, err = hsRun(t, newMem(name), socks0.ModePipelined, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.(*socks0.Conn).BoundAddr(); !b.IsName() || b.Name() != "1.2.3.4" {
		t.Errorf("name BND = %v", b)
	}
}

// Without deadline or ctx only Close ends the handshake.
func TestVerifySilentServerClose(t *testing.T) {
	for _, mode := range modes {
		base := numG()
		mc := newMem()
		c := socks0.Client(mc, "example.com:80", &socks0.Config{Mode: mode})
		errc := make(chan error, 1)
		go func() { errc <- c.HandshakeContext(context.Background()) }()
		time.Sleep(10 * time.Millisecond)
		c.Close()
		select {
		case err := <-errc:
			if !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
				t.Errorf("%v: %v kind %q", mode, err, socks0.KindOf(err))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%v: HandshakeContext hangs after Close", mode)
		}
		checkGoroutines(t, base)
	}
}
