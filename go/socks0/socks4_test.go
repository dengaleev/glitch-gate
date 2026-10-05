package socks0_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var v4 = &socks0.Config{Version: 4}

func cfg4(mode socks0.Mode, auth socks0.Authenticator) *socks0.Config {
	return &socks0.Config{Version: 4, Mode: mode, Auth: auth}
}

func TestSOCKS4Dial(t *testing.T) {
	for _, mode := range modes {
		for _, auth := range []socks0.Authenticator{nil, socks0.UserPass{Username: "alice"}, &socks0.UserPass{Username: "bob"}} {
			for _, target := range []string{"198.51.100.7:80", "example.com:8080"} {
				t.Run(fmt.Sprintf("%v/%v/%s", mode, auth, target), func(t *testing.T) {
					got := make(chan request4, 1)
					conns := make(chan *recConn, 1)
					var ev events
					cfg := cfg4(mode, auth)
					cfg.Trace = ev.trace("t")
					d := &socks0.Dialer{ProxyAddr: listen(t, proxy4{got: got}.serve), ProxyDial: recDial(conns), Config: cfg}
					c := mustDial(t, d, "tcp", target)
					if s := roundTrip(t, c, "hello"); s != "hello" {
						t.Fatalf("echo %q", s)
					}
					want := request4{wire.CmdConnect, mustAddr(target), ""}
					switch a := auth.(type) {
					case socks0.UserPass:
						want.user = a.Username
					case *socks0.UserPass:
						want.user = a.Username
					}
					if r := <-got; r != want {
						t.Errorf("server got %+v, want %+v", r, want)
					}
					writes, _ := (<-conns).snapshot()
					if mode == socks0.ModeEarly {
						if len(writes) == 0 || string(writes[0][len(writes[0])-5:]) != "hello" {
							t.Errorf("first write % x: no early data", writes)
						}
					} else if b, _ := wire.AppendRequest4(nil, wire.CmdConnect, mustAddr(target), want.user); string(writes[0]) != string(b) {
						t.Errorf("first write % x, want % x", writes[0], b)
					}
					if got := only(ev.get(), "t"); !slices.Equal(got, []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotReply 0x5a 0.0.0.0:0", "HandshakeDone ok"}) {
						t.Errorf("trace %q", got)
					}
				})
			}
		}
	}
}

// Local resolution sends an IPv4 address; 0.0.0.x is SOCKS4a's marker, not an address.
func TestSOCKS4Resolver(t *testing.T) {
	got := make(chan request4, 1)
	r := &resolver{ips: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.9")}}
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy4{got: got}.serve), Resolver: r, Config: v4}
	c := mustDial(t, d, "tcp", "example.com:80")
	c.Close()
	if req := <-got; req.addr != mustAddr("192.0.2.9:80") || !slices.Equal(r.got, []string{"ip4 example.com"}) {
		t.Errorf("sent %v, looked up %v", req.addr, r.got)
	}
	r = &resolver{ips: []netip.Addr{netip.MustParseAddr("0.0.0.1")}}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: r, Config: v4}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("resolved to 0.0.0.1: %v", err)
	}
}

// Config errors are found before dialing and never hold the credential.
func TestSOCKS4ConfigErrors(t *testing.T) {
	const secret = "s3cr3t-tok"
	for _, tt := range []struct {
		name    string
		network string
		target  string
		cfg     *socks0.Config
		is      error
	}{
		{"IPv6", "tcp", "[2001:db8::1]:80", v4, wire.ErrInvalid},
		{"tcp6", "tcp6", "example.com:80", v4, nil},
		{"0.0.0.0/24", "tcp", "0.0.0.7:80", v4, wire.ErrInvalid},
		{"NUL", "tcp", "a\x00b:80", v4, wire.ErrInvalid},
		{"password", "tcp", "example.com:80", cfg4(0, socks0.UserPass{Username: "u", Password: secret}), nil},
		{"*UserPass password", "tcp", "example.com:80", cfg4(0, &socks0.UserPass{Username: "u", Password: secret}), nil},
		{"USERID NUL", "tcp", "example.com:80", cfg4(0, socks0.UserPass{Username: secret + "\x00x"}), wire.ErrInvalid},
		{"long USERID", "tcp", "example.com:80", cfg4(0, socks0.UserPass{Username: secret + strings.Repeat("x", 300)}), nil},
		{"nil *UserPass", "tcp", "example.com:80", cfg4(0, (*socks0.UserPass)(nil)), nil},
		{"other auth", "tcp", "example.com:80", cfg4(0, interactive{0x80}), nil},
		{"version 3", "tcp", "example.com:80", &socks0.Config{Version: 3}, nil},
		{"udp", "udp", "192.0.2.1:53", v4, errors.ErrUnsupported},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Config: tt.cfg}
			_, err := d.DialContext(t.Context(), tt.network, tt.target)
			if handshakeErrOf(t, err).Stage != socks0.StageConfig || socks0.KindOf(err) != socks0.KindConfig || tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v", err)
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), secret) {
				t.Errorf("error holds the credential: %v", err)
			}
		})
	}
	d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", Config: v4}
	if _, err := d.ListenPacket(t.Context(), "udp", ""); !errors.Is(err, errors.ErrUnsupported) || socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("ListenPacket: %v", err)
	}
	if _, err := d.Listen(t.Context(), "tcp", ""); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("Listen with no peer: %v", err)
	}
	if err := socks0.Client(nil, "example.com:80", v4).HandshakeContext(t.Context()); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("Client(nil): %v", err)
	}
	// A NUL in the URL's user is rejected, at parse or dial, never echoed.
	u, err := url.Parse("socks4://" + secret + "%00x@proxy:1080")
	if err != nil {
		t.Skip(err)
	}
	p, err := socks0.ParseProxyURL(u)
	if err == nil {
		d := &socks0.Dialer{ProxyAddr: p.Addr, ProxyDial: noDial(t), Config: &p.Config}
		if _, err = d.DialContext(t.Context(), "tcp", "192.0.2.5:80"); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("dial with a NUL user from a URL: %v", err)
		}
	}
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("error holds the credential: %v", err)
	}
}

func TestSOCKS4Errors(t *testing.T) {
	for _, tt := range []struct {
		name string
		p    proxy4
		kind socks0.Kind
		str  string
		is   error
	}{
		{name: "rejected", p: proxy4{cd: wire.Reply4Rejected}, kind: socks0.KindReply, str: "socks4 reply: request rejected or failed"},
		{name: "no identd", p: proxy4{cd: wire.Reply4NoIdentd}, kind: socks0.KindReply, str: "socks4 reply: cannot connect to identd", is: socks0.ErrAuthFailed},
		{name: "ident mismatch", p: proxy4{cd: wire.Reply4IdentMismatch}, kind: socks0.KindReply, str: "socks4 reply: identd user id mismatch", is: socks0.ErrAuthFailed},
		{name: "unknown", p: proxy4{cd: 0x42}, kind: socks0.KindReply, str: "socks4 reply: 0x42"},
		{name: "SOCKS5 server", p: proxy4{raw: []byte{5, 0xFF}}, kind: socks0.KindProtocol, str: "socks4 reply: invalid VER 0x05 (likely a SOCKS5-only server)"},
		{name: "truncated", p: proxy4{raw: []byte{0, 0x5A, 0}}, kind: socks0.KindEOF, str: "socks4 reply: unexpected EOF", is: io.ErrUnexpectedEOF},
		{name: "rejected truncated", p: proxy4{raw: []byte{0, 0x5B, 0}}, kind: socks0.KindReply, str: "socks4 reply: request rejected or failed"},
	} {
		for _, mode := range modes {
			t.Run(tt.name+"/"+mode.String(), func(t *testing.T) {
				d := &socks0.Dialer{ProxyAddr: listen(t, tt.p.serve), Config: cfg4(mode, nil)}
				err := handshakeErr(t.Context(), d, "example.com:80")
				he := handshakeErrOf(t, err)
				if he.Stage != wire.StageReply4 || socks0.KindOf(err) != tt.kind || he.Error() != tt.str || tt.is != nil && !errors.Is(err, tt.is) {
					t.Errorf("err = %q: stage %q, kind %q", he.Error(), he.Stage, socks0.KindOf(err))
				}
				if re, ok := errors.AsType[*socks0.ReplyError](err); ok && (re.Version != 4 || errors.Is(err, errors.ErrUnsupported)) {
					t.Errorf("ReplyError %+v", re)
				}
			})
		}
	}
	t.Run("every CD", func(t *testing.T) {
		for cd := range 256 {
			rep := wire.Reply(cd)
			raw, _ := wire.AppendReply4(nil, rep, wire.Addr{})
			d := &socks0.Dialer{ProxyAddr: listen(t, proxy4{raw: raw}.serve), Config: v4}
			c, err := d.DialContext(t.Context(), "tcp", "192.0.2.5:80")
			if rep == wire.Reply4Granted {
				if err != nil {
					t.Errorf("CD 0x5a: %v", err)
				} else {
					c.Close()
				}
				continue
			}
			re, ok := errors.AsType[*socks0.ReplyError](err)
			if !ok || re.Reply != rep || re.Version != 4 || socks0.KindOf(err) != socks0.KindReply {
				t.Errorf("CD %#x: %v (%q)", cd, err, socks0.KindOf(err))
				continue
			}
			if he := handshakeErrOf(t, err); he.Error() != "socks4 reply: "+wire.Reply4String(rep) || he.Stage != wire.StageReply4 {
				t.Errorf("CD %#x: %q stage %q", cd, he.Error(), he.Stage)
			}
			if auth := rep == wire.Reply4NoIdentd || rep == wire.Reply4IdentMismatch; errors.Is(err, socks0.ErrAuthFailed) != auth {
				t.Errorf("CD %#x: Is(ErrAuthFailed) = %v", cd, !auth)
			}
			// SOCKS5 meanings never leak into SOCKS4 codes.
			if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, socks0.ErrNotPipelinable) {
				t.Errorf("CD %#x matches a SOCKS5 sentinel", cd)
			}
			if k := socks0.KindOf(err); k == socks0.KindRefused || k == socks0.KindUnreachable {
				t.Errorf("CD %#x: kind %q", cd, k)
			}
		}
	})
}

func TestSOCKS4Bind(t *testing.T) {
	got := make(chan request4, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy4{got: got}.serve), Config: cfg4(0, socks0.UserPass{Username: "ftp"})}
	ln := mustListen(t, d, "127.0.0.1:0")
	if r := <-got; r != (request4{wire.CmdBind, mustAddr("127.0.0.1:0"), "ftp"}) {
		t.Errorf("server got %+v", r)
	}
	addr := ln.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || ln.(*socks0.Listener).BoundAddr().IP() != netip.IPv4Unspecified() {
		t.Errorf("Addr %v, BoundAddr %v", addr, ln.(*socks0.Listener).BoundAddr())
	}
	peer, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != peer.LocalAddr().String() {
		t.Errorf("RemoteAddr %v", c.RemoteAddr())
	}
	peer.Write([]byte("x"))
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Error(err)
	}

	// EOF instead of reply 2.
	d = &socks0.Dialer{ProxyAddr: listen(t, func(c net.Conn) {
		if _, _, _, err := wire.ReadRequest4(c); err == nil {
			c.Write(must(wire.AppendReply4(nil, wire.Reply4Granted, mustAddr("0.0.0.0:5555"))))
		}
	}), Config: v4}
	if ln, err = d.Listen(t.Context(), "tcp", "192.0.2.9:0"); err != nil {
		t.Fatal(err)
	}
	if ln.Addr().String() != "127.0.0.1:5555" {
		t.Errorf("Addr = %v", ln.Addr())
	}
	_, err = ln.Accept()
	if pe, ok := errors.AsType[*socks0.ProtocolError](err); !ok || pe.Stage != wire.StageReply4 || socks0.KindOf(err) != socks0.KindEOF {
		t.Errorf("Accept = %v", err)
	}
}

func TestSOCKS4ClientEarly(t *testing.T) {
	conns := make(chan *recConn, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy4{}.serve), ProxyDial: recDial(conns)}
	raw, err := d.ProxyDial(t.Context(), "tcp", d.ProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	c := socks0.Client(raw, "192.0.2.1:7", cfg4(socks0.ModeEarly, nil))
	defer c.Close()
	if s := roundTrip(t, c, "data"); s != "data" {
		t.Errorf("echo %q", s)
	}
	writes, _ := (<-conns).snapshot()
	if req, _ := wire.AppendRequest4(nil, wire.CmdConnect, mustAddr("192.0.2.1:7"), ""); len(writes) != 1 || string(writes[0]) != string(req)+"data" {
		t.Errorf("writes % x", writes)
	}
	if c.BoundAddr() != mustAddr("0.0.0.0:0") {
		t.Errorf("BoundAddr %v", c.BoundAddr())
	}

	// The reply a byte at a time, then the target's data.
	raw, err = net.Dial("tcp", listen(t, func(c net.Conn) {
		if _, _, _, err := wire.ReadRequest4(c); err != nil {
			return
		}
		io.ReadFull(c, make([]byte, 5)) // early data
		for _, x := range append(must(wire.AppendReply4(nil, wire.Reply4Granted, mustAddr("192.0.2.3:7"))), "pong"...) {
			c.Write([]byte{x})
			time.Sleep(time.Millisecond)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	c = socks0.Client(raw, "example.com:80", cfg4(socks0.ModeEarly, nil))
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if s := readN(t, c, 4); s != "pong" || c.BoundAddr().String() != "192.0.2.3:7" {
		t.Errorf("Read = %q, BoundAddr %v", s, c.BoundAddr())
	}
}
