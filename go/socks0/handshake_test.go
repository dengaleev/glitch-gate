package socks0_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// L0 writes each message on its own, L1 the handshake at once, L2 with the first data.
// The dial's ctx and deadlines do not outlive it.
func TestHandshakeWrites(t *testing.T) {
	auth := socks0.UserPass{Username: "u", Password: "p"}
	greet, _ := wire.AppendGreeting(nil, wire.MethodUserPass)
	up, _ := auth.AppendRequest(nil)
	req, _ := wire.AppendRequest(nil, wire.CmdConnect, mustAddr("example.com:80"))
	for _, tt := range []struct {
		mode socks0.Mode
		want [][]byte
	}{
		{socks0.ModeSequential, [][]byte{greet, up, req, []byte("data")}},
		{socks0.ModePipelined, [][]byte{slices.Concat(greet, up, req), []byte("data")}},
		{socks0.ModeEarly, [][]byte{slices.Concat(greet, up, req, []byte("data"))}},
	} {
		t.Run(tt.mode.String(), func(t *testing.T) {
			conns := make(chan *recConn, 1)
			rd := recDial(conns)
			d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve), Config: &socks0.Config{Mode: tt.mode, Auth: auth},
				ProxyDial: func(ctx context.Context, n, a string) (net.Conn, error) {
					c, err := rd(ctx, n, a)
					if err == nil {
						c.SetDeadline(time.Now().Add(time.Hour))
					}
					return c, err
				}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			c, err := d.DialContext(ctx, "tcp", "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			cancel()
			rc := <-conns
			if tt.mode != socks0.ModeEarly && c != net.Conn(rc) {
				t.Fatalf("DialContext returned %T, not the ProxyDial conn", c)
			}
			if rc.mu.Lock(); !rc.dls[len(rc.dls)-1].IsZero() {
				t.Errorf("last deadline %v", rc.dls[len(rc.dls)-1])
			}
			rc.mu.Unlock()
			if _, err := c.Write([]byte("data")); err != nil {
				t.Fatal(err)
			}
			if s := readN(t, c, 4); s != "data" {
				t.Errorf("echo %q", s)
			}
			if writes, _ := rc.snapshot(); !reflect.DeepEqual(writes, tt.want) {
				t.Errorf("writes = % x\nwant     % x", writes, tt.want)
			}
		})
	}
}

// The client reads exactly the replies however the server's bytes are split,
// and leaves the tunnel's first bytes unread.
func TestHandshakeExactRead(t *testing.T) {
	tail := []byte("TUNNEL-DATA-0123456789")
	check := func(t *testing.T, name string, mc *memConn, mode socks0.Mode, withAuth, viaDialer bool, msgs []byte, bound wire.Addr) {
		t.Helper()
		var auth socks0.Authenticator
		if withAuth {
			auth = upAuth
		}
		var gotBound wire.Addr
		c, err := hsRun(t, mc, mode, auth, viaDialer, &socks0.ClientTrace{GotReply: func(_ wire.Reply, b wire.Addr) { gotBound = b }})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer c.Close()
		if consumed, _, asks := mc.stats(); consumed != len(msgs) {
			t.Errorf("%s: consumed %d bytes, replies are %d (asks %v)", name, consumed, len(msgs), asks)
		} else if mode == socks0.ModePipelined && withAuth && asks[0] != 2+2+5 {
			t.Errorf("%s: first Read asks %d bytes; want method, status and the reply's fixed part", name, asks[0])
		}
		if gotBound != bound {
			t.Errorf("%s: GotReply bound %v", name, gotBound)
		}
		if sc, ok := c.(*socks0.Conn); ok && sc.BoundAddr() != bound {
			t.Errorf("%s: BoundAddr %v", name, sc.BoundAddr())
		}
		got := make([]byte, len(tail))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, tail) {
			t.Errorf("%s: tail %q, %v", name, got, err)
		}
	}
	for _, mode := range modes {
		for _, withAuth := range []bool{false, true} {
			for _, b := range []string{"192.0.2.1:1080", "[2001:db8::1]:443", "b.example:7", "x:1", "0.0.0.0:0"} {
				msgs, bound := serverMsgs(withAuth, b), mustAddr(b)
				// All available at once, read in every chunk size.
				for chunk := 1; chunk <= len(msgs)+len(tail); chunk++ {
					for _, viaDialer := range []bool{false, true} {
						mc := newMem(msgs, tail)
						mc.chunk = chunk
						check(t, fmt.Sprintf("%v/auth=%v/%s/chunk=%d/dialer=%v", mode, withAuth, b, chunk, viaDialer), mc, mode, withAuth, viaDialer, msgs, bound)
					}
				}
				// Split at every byte, the rest arriving later.
				for k := 1; k < len(msgs); k++ {
					mc := newMem(msgs[:k])
					time.AfterFunc(time.Millisecond, func() { mc.feed(append(slices.Clip(msgs[k:]), tail...)) })
					check(t, fmt.Sprintf("%v/auth=%v/%s/split=%d", mode, withAuth, b, k), mc, mode, withAuth, false, msgs, bound)
				}
				// A byte at a time, slowly.
				mc := newMem()
				drip(mc, append(slices.Clip(msgs), tail...), time.Millisecond)
				check(t, fmt.Sprintf("%v/auth=%v/%s/slow", mode, withAuth, b), mc, mode, withAuth, false, msgs, bound)
			}
		}
	}
}

// A server sending a byte at a time is waited for; a deadline bounds the wait.
// drip feeds b to mc a byte at a time, every d.
func drip(mc *memConn, b []byte, d time.Duration) {
	go func() {
		for _, x := range b {
			time.Sleep(d)
			mc.feed([]byte{x})
		}
	}()
}

// A deadline bounds the wait for a server sending a byte at a time.
func TestHandshakeSlowServerDeadline(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			mc := newMem()
			drip(mc, serverMsgs(true, "[2001:db8::1]:443")[:5], 10*time.Millisecond) // method, auth status, first reply byte
			c := socks0.Client(mc, "example.com:80", &socks0.Config{Mode: mode, Auth: upAuth})
			c.SetDeadline(time.Now().Add(150 * time.Millisecond))
			err := c.HandshakeContext(context.Background())
			if he := handshakeErrOf(t, err); he.Stage != wire.StageReply || !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout {
				t.Errorf("err %v stage %q kind %q", err, he.Stage, socks0.KindOf(err))
			}
		})
	}
}

// Every kind of server answer, prefilled and followed by EOF, through a Client and
// a Dialer: the error's stage, kind, text and types, and who closes the conn.
func TestHandshakeServerReplies(t *testing.T) {
	huge := slices.Concat([]byte{5, 0, 5, 0, 0, 3, 255}, bytes.Repeat([]byte{'a'}, 255), []byte{0, 80})
	torReply := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0} // Tor answers a bad username format with a SOCKS5 reply
	type row struct {
		name      string
		resp      []byte
		auth      bool
		stage     string
		kind      socks0.Kind // "": success
		str       string      // the HandshakeError's text, if set
		is        error
		field     string // ProtocolError.Field
		hint      string // in ProtocolError.Hint
		badBound  bool   // ReplyError.Bound invalid
		bound     string // success: BND
		boundName bool
	}
	ms, ups, rs := wire.StageMethodSelection, wire.StageUserPassStatus, wire.StageReply
	rows := []row{
		{name: "no acceptable methods", resp: []byte{5, 0xFF}, stage: ms, kind: socks0.KindMethod, is: socks0.ErrNoAcceptableMethods, str: "socks method selection: no acceptable methods (offered no auth)"},
		{name: "no acceptable methods userpass", resp: []byte{5, 0xFF, 9, 9, 9}, auth: true, stage: ms, kind: socks0.KindMethod, is: socks0.ErrNoAcceptableMethods, str: "socks method selection: no acceptable methods (offered username/password)"},
		{name: "method not offered", resp: []byte{5, 2}, stage: ms, kind: socks0.KindMethod, is: socks0.ErrMethodNotOffered, str: "socks method selection: server selected username/password, offered no auth"},
		{name: "GSSAPI not offered", resp: []byte{5, 3, 9, 9}, stage: ms, kind: socks0.KindMethod, is: socks0.ErrMethodNotOffered},
		{name: "no auth, offered userpass", resp: []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, auth: true, stage: ms, kind: socks0.KindMethod, is: socks0.ErrMethodNotOffered},
		{name: "auth rejected", resp: []byte{5, 2, 1, 1}, auth: true, stage: ups, kind: socks0.KindAuth, is: socks0.ErrAuthFailed, str: "socks auth: rejected (username/password status 0x01)"},
		{name: "auth status 0xFF", resp: []byte{5, 2, 1, 0xFF}, auth: true, stage: ups, kind: socks0.KindAuth, is: socks0.ErrAuthFailed},
		{name: "Tor rejects username", resp: append([]byte{5, 2}, torReply...), auth: true, stage: ups, kind: socks0.KindProtocol, field: "VER", hint: "Tor", str: "socks username/password status: invalid VER 0x05 (Tor rejected the username format)"},
		{name: "auth VER 0", resp: []byte{5, 2, 0, 0}, auth: true, stage: ups, kind: socks0.KindProtocol, field: "VER", hint: "SOCKS4"},
		{name: "HTTP proxy", resp: []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), stage: ms, kind: socks0.KindProtocol, field: "VER", hint: "HTTP", str: "socks method selection: invalid VER 0x48 (likely an HTTP proxy)"},
		{name: "SOCKS4 server", resp: []byte{0, 0x5b, 0, 0, 0, 0, 0, 0}, stage: ms, kind: socks0.KindProtocol, field: "VER", hint: "SOCKS4", str: "socks method selection: invalid VER 0x00 (likely a SOCKS4 server)"},
		{name: "VER 4", resp: []byte{4, 0}, stage: ms, kind: socks0.KindProtocol, field: "VER"},
		{name: "reply VER H", resp: []byte("\x05\x00HTTP/1.1 400"), stage: rs, kind: socks0.KindProtocol, field: "VER", hint: "HTTP"},
		{name: "reply VER 0", resp: []byte{5, 0, 0, 0x5a, 0, 0, 0, 0, 0, 0}, stage: rs, kind: socks0.KindProtocol, field: "VER", hint: "SOCKS4"},
		{name: "connection refused", resp: append([]byte{5, 0}, reply(5, "0.0.0.0:0")...), stage: rs, kind: socks0.KindReply, is: eConnRefused, str: "socks reply: connection refused"},
		{name: "command not supported", resp: append([]byte{5, 0}, reply(7, "0.0.0.0:0")...), stage: rs, kind: socks0.KindReply, is: errors.ErrUnsupported, str: "socks reply: command not supported"},
		{name: "TTL expired", resp: append([]byte{5, 0}, reply(6, "0.0.0.0:0")...), stage: rs, kind: socks0.KindReply},
		{name: "unknown reply", resp: append([]byte{5, 0}, reply(0x5b, "0.0.0.0:0")...), stage: rs, kind: socks0.KindReply, str: "socks reply: 0x5b"},
		{name: "tor reply", resp: append([]byte{5, 0}, reply(0xF6, "0.0.0.0:0")...), stage: rs, kind: socks0.KindReply, str: "socks reply: tor: onion service invalid address"},
		{name: "refused, malformed tail", resp: []byte{5, 0, 5, 5, 0, 9, 9, 9}, stage: rs, kind: socks0.KindReply, is: eConnRefused, badBound: true, str: "socks reply: connection refused"},
		{name: "refused, truncated", resp: []byte{5, 0, 5, 5, 0, 1, 1}, stage: rs, kind: socks0.KindReply, is: eConnRefused, badBound: true, str: "socks reply: connection refused"},
		{name: "REP 1 ATYP 0", resp: []byte{5, 0, 5, 1, 0, 0, 1, 2, 3, 4, 0, 80}, stage: rs, kind: socks0.KindReply, badBound: true},
		{name: "REP 5 domain len 0", resp: []byte{5, 0, 5, 5, 0, 3, 0}, stage: rs, kind: socks0.KindReply, badBound: true},
		{name: "REP 0xFF garbage", resp: []byte{5, 0, 5, 0xFF, 0xFF, 0xFF, 0xFF}, stage: rs, kind: socks0.KindReply, badBound: true},
		{name: "bad ATYP", resp: []byte{5, 0, 5, 0, 0, 9, 9, 9}, stage: rs, kind: socks0.KindProtocol, field: "ATYP", str: "socks reply: invalid ATYP 0x09"},
		{name: "ATYP 0", resp: []byte{5, 0, 5, 0, 0, 0, 1, 2, 3, 4, 0, 80}, stage: rs, kind: socks0.KindProtocol, field: "ATYP"},
		{name: "ATYP 2", resp: []byte{5, 0, 5, 0, 0, 2, 1, 2, 3, 4, 0, 80}, stage: rs, kind: socks0.KindProtocol, field: "ATYP"},
		{name: "domain len 0", resp: []byte{5, 0, 5, 0, 0, 3, 0, 0, 80}, stage: rs, kind: socks0.KindProtocol, field: "ADDR"},
		{name: "RSV nonzero", resp: []byte{5, 0, 5, 0, 0xEE, 1, 1, 2, 3, 4, 0, 80}, bound: "1.2.3.4:80"},
		{name: "huge domain BND", resp: huge, bound: strings.Repeat("a", 255) + ":80", boundName: true},
		{name: "IPv4-mapped BND unmapped", resp: []byte{5, 0, 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4, 0, 80}, bound: "1.2.3.4:80"},
		{name: "domain BND 1.2.3.4 stays a name", resp: append([]byte{5, 0, 5, 0, 0, 3, 7}, "1.2.3.4\x00\x50"...), bound: "1.2.3.4:80", boundName: true},
	}
	for _, auth := range []bool{false, true} { // EOF after each byte of good replies
		msgs := serverMsgs(auth, "b.example:7")
		for k := range len(msgs) {
			stage := ms
			if auth && k >= 2 {
				stage = ups
			}
			if !auth && k >= 2 || k >= 4 {
				stage = rs
			}
			rows = append(rows, row{name: fmt.Sprintf("EOF after %d, auth=%v", k, auth), resp: msgs[:k], auth: auth, stage: stage,
				kind: socks0.KindEOF, is: io.ErrUnexpectedEOF, str: "socks " + stage + ": unexpected EOF"})
		}
	}
	for _, tt := range rows {
		for _, mode := range modes {
			for _, viaDialer := range []bool{false, true} {
				name := fmt.Sprintf("%s/%v/dialer=%v", tt.name, mode, viaDialer)
				mc := newMem(tt.resp)
				mc.closeServer()
				var auth socks0.Authenticator
				if tt.auth {
					auth = upAuth
				}
				var replies []wire.Addr
				c, err := hsRun(t, mc, mode, auth, viaDialer, &socks0.ClientTrace{GotReply: func(_ wire.Reply, b wire.Addr) { replies = append(replies, b) }})
				// An L0/L1 Dialer closes a failed conn and returns the raw one; a Conn closes only on Close, once.
				switch sc, isConn := c.(*socks0.Conn); {
				case isConn:
					if mc.closes.Load() != 0 {
						t.Errorf("%s: closed before Close", name)
					}
					sc.Close()
					sc.Close()
					if n := mc.closes.Load(); n != 1 {
						t.Errorf("%s: Close closed %d times", name, n)
					}
				case err != nil:
					if c != nil || mc.closes.Load() != 1 {
						t.Errorf("%s: conn %v, closed %d times", name, c, mc.closes.Load())
					}
				default:
					if c != net.Conn(mc) || mc.closes.Load() != 0 {
						t.Errorf("%s: conn %T, closed %d times", name, c, mc.closes.Load())
					}
					c.Close()
				}
				if tt.kind == "" {
					if err != nil || len(replies) != 1 || replies[0].String() != tt.bound || replies[0].IsName() != tt.boundName {
						t.Errorf("%s: %v, BND %v", name, err, replies)
					}
					continue
				}
				if err == nil {
					t.Errorf("%s: no error", name)
					continue
				}
				he := handshakeErrOf(t, err)
				if he.Stage != tt.stage || socks0.KindOf(err) != tt.kind || tt.str != "" && he.Error() != tt.str || tt.is != nil && !errors.Is(err, tt.is) {
					t.Errorf("%s: %q (stage %q, kind %q)", name, he.Error(), he.Stage, socks0.KindOf(err))
				}
				if err.(*net.OpError).Timeout() || strings.Contains(err.Error(), "S3CRET") {
					t.Errorf("%s: %v is a timeout or holds the password", name, err)
				}
				if pe, ok := errors.AsType[*socks0.ProtocolError](err); ok {
					if pe.Field != tt.field || pe.Stage != he.Stage || !strings.Contains(pe.Hint, tt.hint) {
						t.Errorf("%s: ProtocolError %+v", name, pe)
					}
				} else if tt.field != "" {
					t.Errorf("%s: want a ProtocolError, got %v", name, err)
				}
				re, isReply := errors.AsType[*socks0.ReplyError](err)
				if isReply != (len(replies) == 1) || len(replies) > 1 {
					t.Errorf("%s: GotReply ran for %v", name, replies)
				}
				if isReply && re.Bound.IsValid() == tt.badBound {
					t.Errorf("%s: Bound = %v", name, re.Bound)
				}
			}
		}
	}
}

// A failed handshake write fails at the first message not fully written; data
// failing after the handshake is a plain write error.
func TestHandshakeWriteFailure(t *testing.T) {
	auth := socks0.UserPass{Username: "u", Password: "p"} // greeting 3, auth 5, request 18
	for _, tt := range []struct {
		n     int
		stage string
	}{{0, wire.StageGreeting}, {2, wire.StageGreeting}, {3, wire.StageUserPass}, {7, wire.StageUserPass}, {8, wire.StageRequest}, {25, wire.StageRequest}} {
		for _, mode := range modes {
			mc := newMem(serverMsgs(true, "192.0.2.1:1080"))
			mc.failAfter(tt.n)
			d := &socks0.Dialer{ProxyDial: memDial(mc), Config: &socks0.Config{Mode: mode, Auth: auth}}
			c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if mode == socks0.ModeEarly {
				var n int
				if n, err = c.Write([]byte("data")); n != 0 {
					t.Errorf("Write = %d", n)
				}
				if _, err2 := c.Read(nil); err2 != err {
					t.Errorf("Read = %v; want sticky %v", err2, err)
				}
				c.Close()
			}
			if he := handshakeErrOf(t, err); he.Stage != tt.stage || he.Err != errTest {
				t.Errorf("%v after %d bytes: %v (stage %q)", mode, tt.n, err, he.Stage)
			}
		}
	}
	mc := newMem(goodReplies)
	mc.failAfter(len(hsNoAuth) + 2)
	c := socks0.Client(mc, "example.com:80", early())
	if n, err := c.Write([]byte("data")); n != 2 || err != errTest {
		t.Errorf("Write = %d, %v; want the data's short count and error", n, err)
	}
	if err := c.HandshakeContext(t.Context()); err != nil {
		t.Errorf("HandshakeContext = %v", err)
	}
	if w := mc.written(); string(w) != string(hsNoAuth)+"da" {
		t.Errorf("wrote %q", w)
	}
}

func TestHandshakeCustomAuth(t *testing.T) {
	serve := func(authReply string, n int) func(net.Conn) {
		return func(c net.Conn) {
			if _, err := wire.ReadGreeting(c); err != nil {
				return
			}
			c.Write([]byte{5, 0x80})
			io.ReadFull(c, make([]byte, n))
			c.Write([]byte(authReply))
			if _, _, err := wire.ReadRequest(c); err != nil {
				return
			}
			c.Write(append(reply(0, "192.0.2.1:1080"), "tail"...))
			io.Copy(io.Discard, c)
		}
	}
	for _, tt := range []struct {
		name  string
		mode  socks0.Mode
		auth  socks0.Authenticator
		srv   func(net.Conn)
		stage string // "": success
		kind  socks0.Kind
	}{
		{"pipelined", socks0.ModePipelined, pipeliner{}, serve("ok!", 1), "", ""},
		{"long reply", socks0.ModePipelined, pipeliner{size: 1000}, serve("ok!"+strings.Repeat(".", 997), 1), "", ""},
		{"too long reply", socks0.ModePipelined, pipeliner{size: 100 << 10}, serve("ok!", 1), socks0.StageAuth, ""},
		{"pipelined rejected", socks0.ModePipelined, pipeliner{}, serve("no!", 1), socks0.StageAuth, socks0.KindAuth},
		{"early", socks0.ModeEarly, pipeliner{}, serve("ok!", 1), "", ""},
		{"sequential", socks0.ModeSequential, interactive{0x80}, serve("\x00", 2), "", ""},
		{"sequential rejected", socks0.ModeSequential, interactive{0x80}, serve("\x01", 2), socks0.StageAuth, socks0.KindAuth},
		{"sequential eof", socks0.ModeSequential, interactive{0x80}, scripted([]byte{5, 0x80}, false), socks0.StageAuth, socks0.KindEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var authDone []error
			cfg := &socks0.Config{Mode: tt.mode, Auth: tt.auth, Trace: &socks0.ClientTrace{
				AuthDone: func(err error) { authDone = append(authDone, err) },
			}}
			d := &socks0.Dialer{ProxyAddr: listen(t, tt.srv), Config: cfg}
			err := handshakeErr(t.Context(), d, "example.com:80")
			if len(authDone) != 1 || !errors.Is(err, authDone[0]) {
				t.Errorf("AuthDone ran with %v; err %v", authDone, err)
			}
			if tt.stage == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if he := handshakeErrOf(t, err); he.Stage != tt.stage || tt.kind != "" && socks0.KindOf(err) != tt.kind {
				t.Errorf("stage %q, kind %q, err %v", he.Stage, socks0.KindOf(err), err)
			}
		})
	}
}

func TestHandshakeUserPassAuthenticate(t *testing.T) {
	long := strings.Repeat("x", 256)
	var buf bytes.Buffer
	if err := (socks0.UserPass{Username: long}).Authenticate(t.Context(), &buf); !errors.Is(err, wire.ErrInvalid) || buf.Len() != 0 {
		t.Errorf("long name: %v", err)
	}
	buf.Write([]byte{1, 0})
	if err := (socks0.UserPass{Username: "u", Password: "p"}).Authenticate(t.Context(), &buf); err != nil {
		t.Error(err)
	}
	if got := buf.String(); got != "\x01\x01u\x01p" {
		t.Errorf("request %q", got)
	}
	buf.Reset()
	buf.Write([]byte{1, 3})
	if err := (socks0.UserPass{}).Authenticate(t.Context(), &buf); err.Error() != "socks auth: rejected (username/password status 0x03)" {
		t.Errorf("rejection: %v", err)
	}
	mc := newMem()
	mc.failAfter(0)
	if err := (socks0.UserPass{}).Authenticate(t.Context(), mc); err != errTest {
		t.Errorf("write error: %v", err)
	}
}

func TestHandshakeOfferNoAuth(t *testing.T) {
	up := socks0.UserPass{Username: "u", Password: "p"}
	for _, tc := range []struct {
		name     string
		choose   wire.Method
		authDone bool
		is       error
		msg      string
	}{
		{name: "server takes no auth", choose: wire.MethodNoAuth},
		{name: "server takes user/pass", choose: wire.MethodUserPass, authDone: true},
		{name: "no acceptable", choose: wire.MethodNoAcceptable, is: socks0.ErrNoAcceptableMethods,
			msg: "socks method selection: no acceptable methods (offered username/password, no auth)"},
		{name: "not offered", choose: wire.MethodGSSAPI, is: socks0.ErrMethodNotOffered,
			msg: "socks method selection: server selected GSSAPI, offered username/password, no auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan request, 1)
			var authDone bool
			d := &socks0.Dialer{ProxyAddr: listen(t, proxy{method: &tc.choose, got: got}.serve), Config: &socks0.Config{
				Mode: socks0.ModeSequential, Auth: up, OfferNoAuth: true,
				Trace: &socks0.ClientTrace{AuthDone: func(error) { authDone = true }},
			}}
			c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if r := <-got; !slices.Equal(r.methods, []wire.Method{wire.MethodUserPass, wire.MethodNoAuth}) {
				t.Errorf("offered %v", r.methods)
			}
			if tc.is != nil {
				me, ok := errors.AsType[*socks0.MethodError](err)
				if !ok || !errors.Is(err, tc.is) || !me.OfferedNoAuth || err.(*net.OpError).Err.Error() != tc.msg {
					t.Errorf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if authDone != tc.authDone {
				t.Errorf("AuthDone ran: %v", authDone)
			}
			c.Write([]byte("hi"))
			if s := readN(t, c, 2); s != "hi" {
				t.Errorf("echo %q", s)
			}
		})
	}
	// With no Auth there is nothing to add: one method, as without it.
	mc := newMem(goodReplies)
	c := socks0.Client(mc, "192.0.2.2:80", &socks0.Config{Mode: socks0.ModeSequential, OfferNoAuth: true})
	if err := c.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := mc.written(); !slices.Equal(w[:3], []byte{5, 1, 0}) {
		t.Errorf("greeting % x", w[:3])
	}
}

// No error, error chain or trace hook argument holds the password.
func TestHandshakePasswordNeverLeaks(t *testing.T) {
	const pw = "PW-7c1f5e"
	auth := socks0.UserPass{Username: "alice", Password: pw}
	var (
		mu   sync.Mutex
		seen []string
	)
	note := func(s string) { mu.Lock(); seen = append(seen, s); mu.Unlock() }
	tr := &socks0.ClientTrace{
		ConnectDone:    func(n, a string, err error) { note(fmt.Sprint(n, a, err)) },
		WroteHandshake: func(err error) { note(fmt.Sprint(err)) },
		AuthDone:       func(err error) { note(fmt.Sprint(err)) },
		HandshakeDone:  func(err error) { note(fmt.Sprint(err)) },
	}
	for _, s := range [][]byte{nil, {5}, {5, 2}, {5, 2, 1}, {5, 2, 1, 1}, {5, 2, 5, 1}, {5, 2, 1, 0, 5, 1}, []byte("HTTP/1.1 407"), {5, 0xFF}, {5, 0}} {
		for _, mode := range modes {
			for _, viaDialer := range []bool{true, false} {
				mc := newMem(s)
				mc.closeServer()
				c, err := hsRun(t, mc, mode, auth, viaDialer, tr)
				if c != nil {
					c.Close()
				}
				note(fmt.Sprintf("%v|%+v|%s", err, err, err))
				for e := err; e != nil; e = errors.Unwrap(e) {
					note(e.Error())
				}
			}
		}
	}
	// A write failing mid-auth (L0), and a config error.
	mc := newMem([]byte{5, 2})
	mc.onWrite = func(b []byte) (int, error) {
		if len(b) > 3 {
			return 1, errors.New("write failed")
		}
		return len(b), nil
	}
	_, err := hsRun(t, mc, socks0.ModeSequential, auth, true, tr)
	note(fmt.Sprint(err))
	_, err = (&socks0.Dialer{Config: &socks0.Config{Auth: socks0.UserPass{Username: "u", Password: pw + strings.Repeat("x", 300)}}}).Dial("tcp", "x:1")
	note(fmt.Sprint(err))
	for _, s := range seen {
		if strings.Contains(s, pw) {
			t.Errorf("password leaked: %s", s)
		}
	}
}

// The client zeroes the password in the buffers it wrote (best effort: the strings in Config stay).
func TestHandshakeWipesPassword(t *testing.T) {
	addr := listen(t, proxy{}.serve)
	for _, mode := range modes {
		for _, auth := range []socks0.Authenticator{socks0.UserPass{Username: "alice", Password: "hunter2"}, &socks0.UserPass{Username: "alice", Password: "hunter2"}} {
			conns := make(chan *recConn, 1)
			d := &socks0.Dialer{ProxyAddr: addr, ProxyDial: recDial(conns), Config: &socks0.Config{Mode: mode, Auth: auth}}
			c := mustDial(t, d, "tcp", "example.com:80")
			c.Write([]byte("ping"))
			if s := readN(t, c, 4); s != "ping" {
				t.Fatalf("%v: echo %q", mode, s)
			}
			c.Close()
			rc := <-conns
			rc.mu.Lock()
			for _, w := range rc.passed {
				if bytes.Contains(w, []byte("hunter2")) {
					t.Errorf("%v %T: the password is still in a written buffer: %q", mode, auth, w)
				}
			}
			rc.mu.Unlock()
		}
	}
}
