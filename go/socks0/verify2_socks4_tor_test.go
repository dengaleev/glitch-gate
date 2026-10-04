package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestV2SOCKS4NoCredentialsInErrors(t *testing.T) {
	const secret = "s3cr3t-tok"
	for _, tc := range []struct {
		name string
		auth socks0.Authenticator
	}{
		{"NUL in username", socks0.UserPass{Username: secret + "\x00x"}},
		{"long username", socks0.UserPass{Username: secret + strings.Repeat("x", 300)}},
		{"password", socks0.UserPass{Username: "u", Password: secret}},
		{"*UserPass password", &socks0.UserPass{Username: "u", Password: secret}},
	} {
		d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Config: &socks0.Config{Version: 4, Auth: tc.auth}}
		_, err := d.DialContext(t.Context(), "tcp", "192.0.2.5:80")
		if socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), secret) {
			t.Errorf("%s: error holds the credential: %v", tc.name, err)
		}
	}
	// A NUL in the userinfo is rejected (at parse or dial), never echoed.
	u, err := url.Parse("socks4://" + secret + "%00x@proxy:1080")
	if err != nil {
		t.Skip(err)
	}
	p, err := socks0.ParseProxyURL(u)
	if err != nil {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("ParseProxyURL error holds the credential: %v", err)
		}
		return
	}
	d := &socks0.Dialer{ProxyAddr: p.Addr, ProxyDial: noDial(t), Config: &p.Config}
	_, err = d.DialContext(t.Context(), "tcp", "192.0.2.5:80")
	if socks0.KindOf(err) != socks0.KindConfig || strings.Contains(err.Error(), secret) {
		t.Errorf("dial with NUL username from URL: %v", err)
	}
	t.Logf("note: ParseProxyURL accepts a NUL in a socks4 username; the dial fails: %v", err)
}

func TestV2SOCKS4ReplyCodes(t *testing.T) {
	for cd := range 256 {
		rep := wire.Reply(cd)
		raw, _ := wire.AppendReply4(nil, rep, wire.Addr{})
		d := &socks0.Dialer{ProxyAddr: listen(t, proxy4{raw: raw}.serve), Config: &socks0.Config{Version: 4}}
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
		want := "socks4 reply: " + wire.Reply4String(rep)
		if he := handshakeErrOf(t, err); he.Error() != want || he.Stage != wire.StageReply4 {
			t.Errorf("CD %#x: %q stage %q", cd, he.Error(), he.Stage)
		}
		auth := rep == wire.Reply4NoIdentd || rep == wire.Reply4IdentMismatch
		if errors.Is(err, socks0.ErrAuthFailed) != auth {
			t.Errorf("CD %#x: Is(ErrAuthFailed) = %v", cd, !auth)
		}
		// SOCKS5 meanings never leak into SOCKS4 codes
		if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, socks0.ErrNotPipelinable) {
			t.Errorf("CD %#x matches a SOCKS5 sentinel", cd)
		}
		if k := socks0.KindOf(err); k == socks0.KindRefused || k == socks0.KindUnreachable {
			t.Errorf("CD %#x: kind %q", cd, k)
		}
	}
}

func TestV2SOCKS4ResolverZeroNet(t *testing.T) {
	r := &recResolver{ips: []netip.Addr{netip.MustParseAddr("0.0.0.1")}}
	d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: r, Config: &socks0.Config{Version: 4}}
	_, err := d.DialContext(t.Context(), "tcp", "example.com:80")
	if socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("err = %v", err)
	}
}

func TestV2SOCKS4EarlySplitReply(t *testing.T) {
	addr := listen(t, func(c net.Conn) {
		if _, _, _, err := wire.ReadRequest4(c); err != nil {
			return
		}
		b := make([]byte, 5)
		io.ReadFull(c, b) // early data
		rep, _ := wire.AppendReply4(nil, wire.Reply4Granted, mustAddr("192.0.2.3:7"))
		for _, x := range append(rep, "pong"...) {
			c.Write([]byte{x})
			time.Sleep(time.Millisecond)
		}
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := socks0.Client(raw, "example.com:80", &socks0.Config{Version: 4, Mode: socks0.ModeEarly})
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(io.LimitReader(c, 4))
	if err != nil || string(got) != "pong" {
		t.Errorf("Read = %q %v", got, err)
	}
	if c.BoundAddr().String() != "192.0.2.3:7" {
		t.Errorf("BoundAddr %v", c.BoundAddr())
	}
}

// Tor extended errors on CONNECT, with ATYP 0 as Tor sends them.
func TestV2TorExtendedErrors(t *testing.T) {
	for rep := wire.Reply(0xF0); rep <= 0xF7; rep++ {
		for _, atyp0 := range []bool{true, false} {
			var resp []byte
			if atyp0 {
				resp = []byte{5, byte(rep), 0, 0, 0, 0, 0, 0, 0, 0}
			} else {
				resp = reply(rep, "0.0.0.0:0")
			}
			d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: resp}.serve)}
			_, err := d.DialContext(t.Context(), "tcp", "abcdef.onion:80")
			re, ok := errors.AsType[*socks0.ReplyError](err)
			if !ok || re.Reply != rep || socks0.KindOf(err) != socks0.KindReply {
				t.Errorf("rep %#x atyp0=%v: %v", rep, atyp0, err)
				continue
			}
			if s := errors.Unwrap(err).Error(); !strings.HasPrefix(s, "socks reply: tor: onion service") {
				t.Errorf("rep %#x: %q", rep, s)
			}
			if errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("rep %#x matches ErrUnsupported", rep)
			}
		}
	}
}

func TestV2LookupAddrIPv6(t *testing.T) {
	got := make(chan cmdAddr, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: reply(0, "v6.example:0"), got: got}.serve)}
	names, err := d.LookupAddr(t.Context(), "2001:db8::5")
	if err != nil || len(names) != 1 || names[0] != "v6.example" {
		t.Fatalf("LookupAddr = %v %v", names, err)
	}
	if r := <-got; r.cmd != wire.CmdTorResolvePTR || r.addr != mustAddr("[2001:db8::5]:0") || r.addr.ATYP() != wire.ATYPIPv6 {
		t.Errorf("request %v", r)
	}
	// failure with ATYP 0 for PTR
	d = &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: []byte{5, 4, 0, 0, 0, 0, 0, 0, 0, 0}}.serve)}
	_, err = d.LookupAddr(t.Context(), "2001:db8::5")
	de, ok := err.(*net.DNSError)
	if !ok || !de.IsNotFound || de.Name != "2001:db8::5" {
		t.Errorf("LookupAddr REP 04: %#v", err)
	}
	if oe, ok := de.UnwrapErr.(*net.OpError); !ok || oe.Op != "socks resolve ptr" {
		t.Errorf("UnwrapErr %#v", de.UnwrapErr)
	}
}

func TestV2LookupCancel(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{hang: true}.serve)}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(30*time.Millisecond, cancel)
	_, err := d.LookupNetIP(ctx, "ip", "example.com")
	de, ok := err.(*net.DNSError)
	if !ok || de.IsTimeout || de.IsNotFound || !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled {
		t.Errorf("err = %#v (%q)", err, socks0.KindOf(err))
	}
	if ok && (strings.Contains(de.Err, "192.0.2") || strings.Contains(de.Err, "127.0.0.1")) {
		t.Errorf("DNSError.Err holds an address: %q", de.Err)
	}
}

// The RESOLVE's REP must not look like the CONNECT's reply.
func TestV2DialerAsResolverErrors(t *testing.T) {
	tor := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: []byte{5, 4, 0, 0, 0, 0, 0, 0, 0, 0}}.serve)}
	d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: tor}
	_, err := d.DialContext(t.Context(), "tcp", "nx.example:80")
	he := handshakeErrOf(t, err)
	if he.Stage != socks0.StageResolve {
		t.Errorf("stage %q", he.Stage)
	}
	de, ok := errors.AsType[*net.DNSError](err)
	if !ok || !de.IsNotFound {
		t.Errorf("no not-found DNSError: %v", err)
	}
	if k := socks0.KindOf(err); k != socks0.KindDNS {
		t.Errorf("KindOf = %q, want dns (A2: KindDNS is 'resolving ... (Resolver) the target'); err %v", k, err)
	}
	if _, ok := errors.AsType[*socks0.ReplyError](err); ok {
		t.Errorf("errors.As(*ReplyError) finds the Tor RESOLVE's REP 04 inside a CONNECT dial error: %v", err)
	}
	if !socks0.IsProxyError(err) {
		t.Errorf("IsProxyError(%v) = false", err)
	}
	// LookupNetIP itself keeps the RESOLVE's reply reachable.
	if _, err := tor.LookupNetIP(t.Context(), "ip", "nx.example"); err == nil {
		t.Error("LookupNetIP: no error")
	} else if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyHostUnreachable {
		t.Errorf("LookupNetIP err %v: no *ReplyError", err)
	}
	// Canceled while the Dialer resolves: still canceled.
	hang := &socks0.Dialer{ProxyAddr: listen(t, torProxy{hang: true}.serve)}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: hang}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)
	_, err = d.DialContext(ctx, "tcp", "nx.example:80")
	if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled || handshakeErrOf(t, err).Stage != socks0.StageResolve {
		t.Errorf("canceled resolve: %v (kind %q)", err, socks0.KindOf(err))
	}
	// a Resolver Dialer whose own config is broken (SOCKS4 has no RESOLVE)
	tor4 := &socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t), Config: &socks0.Config{Version: 4}}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: tor4}
	_, err = d.DialContext(t.Context(), "tcp", "nx.example:80")
	if k, st := socks0.KindOf(err), handshakeErrOf(t, err).Stage; k != socks0.KindDNS || st != socks0.StageResolve {
		t.Errorf("resolver misconfigured: KindOf = %q, stage %q: %v", k, st, err)
	}
}
