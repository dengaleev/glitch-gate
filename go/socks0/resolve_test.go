package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestLookupNetIP(t *testing.T) {
	ip4, ip6 := reply(0, "192.0.2.1:0"), reply(0, "[2001:db8::1]:0")
	for _, mode := range modes {
		for _, tt := range []struct {
			network string
			reply   []byte
			want    string
		}{
			{"ip", ip4, "192.0.2.1"},
			{"ip4", ip4, "192.0.2.1"},
			{"ip", ip6, "2001:db8::1"},
			{"ip6", ip6, "2001:db8::1"},
			{"ip6", ip4, ""},
			{"ip4", ip6, ""},
		} {
			t.Run(fmt.Sprint(mode, "/", tt.network, "/", tt.want), func(t *testing.T) {
				got := make(chan request, 1)
				auth := socks0.UserPass{Username: "isolation", Password: "x"}
				d := &socks0.Dialer{ProxyAddr: listen(t, answer(tt.reply, got, false)), Config: &socks0.Config{Mode: mode, Auth: auth}}
				ips, err := d.LookupNetIP(t.Context(), tt.network, "example.com")
				if r := <-got; r.cmd != wire.CmdTorResolve || r.target != mustAddr("example.com:0") || r.user != "isolation" {
					t.Errorf("request %+v", r)
				}
				if tt.want == "" {
					if de, ok := err.(*net.DNSError); !ok || !de.IsNotFound || de.Name != "example.com" || de.Server != d.ProxyAddr {
						t.Errorf("err = %#v; want not found", err)
					}
					return
				}
				if err != nil || !slices.Equal(ips, []netip.Addr{netip.MustParseAddr(tt.want)}) {
					t.Errorf("LookupNetIP = %v, %v", ips, err)
				}
			})
		}
	}
}

func TestLookupLiteral(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t)}
	ips, err := d.LookupNetIP(t.Context(), "ip", "2001:db8::7")
	if err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("2001:db8::7") {
		t.Errorf("LookupNetIP = %v, %v", ips, err)
	}
	if _, err := d.LookupNetIP(t.Context(), "ip4", "2001:db8::7"); err == nil || !err.(*net.DNSError).IsNotFound {
		t.Errorf("ip4 of an IPv6 literal: %v", err)
	}
	hosts, err := d.LookupHost(t.Context(), "192.0.2.7")
	if err != nil || !slices.Equal(hosts, []string{"192.0.2.7"}) {
		t.Errorf("LookupHost = %v, %v", hosts, err)
	}
}

var refused = []byte{5, 4, 0, 0, 0, 0, 0, 0, 0, 0} // REP 04, ATYP 0, as Tor sends it

func TestLookupErrors(t *testing.T) {
	for _, tt := range []struct {
		name     string
		reply    []byte
		notFound bool
		kind     socks0.Kind
		is       error
	}{
		{name: "REP 04 ATYP 0", reply: refused, notFound: true, kind: socks0.KindReply},
		{name: "REP 01", reply: reply(1, "0.0.0.0:0"), kind: socks0.KindReply},
		{name: "not Tor", reply: reply(7, "0.0.0.0:0"), kind: socks0.KindReply, is: errors.ErrUnsupported},
		{name: "a name", reply: reply(0, "example.net:0"), kind: socks0.KindProtocol},
		{name: "truncated", reply: []byte{5, 0, 0, 1, 1}, kind: socks0.KindEOF, is: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: listen(t, answer(tt.reply, nil, false))}
			_, err := d.LookupHost(t.Context(), "example.com")
			de, ok := err.(*net.DNSError)
			if !ok || de.IsNotFound != tt.notFound || de.Name != "example.com" || de.Server != d.ProxyAddr || de.IsTimeout {
				t.Fatalf("err = %#v", err)
			}
			if oe, ok := de.UnwrapErr.(*net.OpError); !ok || oe.Op != "socks resolve" || socks0.KindOf(err) != tt.kind || tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v; kind %q", err, socks0.KindOf(err))
			}
			if tt.notFound && de.Err != "no such host" {
				t.Errorf("Err %q", de.Err)
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: listen(t, answer(nil, nil, true))}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		_, err := d.LookupNetIP(ctx, "ip", "example.com")
		if de, ok := err.(*net.DNSError); !ok || !de.IsTimeout || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %#v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: listen(t, answer(nil, nil, true))}
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
	})
	t.Run("config", func(t *testing.T) {
		for _, f := range []func(d *socks0.Dialer) error{
			func(d *socks0.Dialer) error { _, err := d.LookupNetIP(t.Context(), "tcp", "example.com"); return err },
			func(d *socks0.Dialer) error {
				_, err := d.LookupNetIP(t.Context(), "ip", string(make([]byte, 256)))
				return err
			},
			func(d *socks0.Dialer) error {
				d.Config = v4
				_, err := d.LookupHost(t.Context(), "example.com")
				return err
			},
			func(d *socks0.Dialer) error {
				d.Config = v4
				_, err := d.LookupAddr(t.Context(), "192.0.2.1")
				return err
			},
		} {
			err := f(&socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t)})
			if _, ok := err.(*net.DNSError); !ok || socks0.KindOf(err) != socks0.KindConfig {
				t.Errorf("err = %#v", err)
			}
		}
	})
}

func TestLookupAddr(t *testing.T) {
	for _, tt := range []struct{ ip, name, req string }{
		{"192.0.2.1", "host.example", "192.0.2.1:0"},
		{"2001:db8::5", "v6.example", "[2001:db8::5]:0"},
	} {
		got := make(chan request, 1)
		d := &socks0.Dialer{ProxyAddr: listen(t, answer(reply(0, tt.name+":0"), got, false))}
		names, err := d.LookupAddr(t.Context(), tt.ip)
		if err != nil || !slices.Equal(names, []string{tt.name}) {
			t.Fatalf("LookupAddr = %v, %v", names, err)
		}
		if r := <-got; r.cmd != wire.CmdTorResolvePTR || r.target != mustAddr(tt.req) {
			t.Errorf("request %+v", r)
		}
	}
	d := &socks0.Dialer{ProxyAddr: listen(t, answer(reply(0, "192.0.2.1:0"), nil, false))}
	if _, err := d.LookupAddr(t.Context(), "192.0.2.1"); socks0.KindOf(err) != socks0.KindProtocol {
		t.Errorf("PTR answered with an IP: %v", err)
	}
	d = &socks0.Dialer{ProxyAddr: listen(t, answer(refused, nil, false))}
	_, err := d.LookupAddr(t.Context(), "2001:db8::5")
	de, ok := err.(*net.DNSError)
	if !ok || !de.IsNotFound || de.Name != "2001:db8::5" {
		t.Errorf("LookupAddr REP 04: %#v", err)
	} else if oe, ok := de.UnwrapErr.(*net.OpError); !ok || oe.Op != "socks resolve ptr" {
		t.Errorf("UnwrapErr %#v", de.UnwrapErr)
	}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t)}
	if _, err := d.LookupAddr(t.Context(), "host.example"); err == nil || err.(*net.DNSError).Err != "unrecognized address" {
		t.Errorf("LookupAddr of a name: %v", err)
	}
}

// A Dialer resolves for another; its RESOLVE's failure is a DNS error of the CONNECT, not a reply.
func TestDialerAsResolver(t *testing.T) {
	var _ socks0.Resolver = (*socks0.Dialer)(nil)
	tor := &socks0.Dialer{ProxyAddr: listen(t, answer(reply(0, "192.0.2.80:0"), nil, false))}
	got := make(chan request, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve), Resolver: tor}
	c := mustDial(t, d, "tcp4", "example.com:80")
	c.Close()
	if r := <-got; r.target != mustAddr("192.0.2.80:80") {
		t.Errorf("target %v", r.target)
	}

	tor = &socks0.Dialer{ProxyAddr: listen(t, answer(refused, nil, false))}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: tor}
	_, err := d.DialContext(t.Context(), "tcp", "nx.example:80")
	if he := handshakeErrOf(t, err); he.Stage != socks0.StageResolve || socks0.KindOf(err) != socks0.KindDNS || !socks0.IsProxyError(err) {
		t.Errorf("stage %q, kind %q: %v", he.Stage, socks0.KindOf(err), err)
	}
	if de, ok := errors.AsType[*net.DNSError](err); !ok || !de.IsNotFound {
		t.Errorf("no not-found DNSError: %v", err)
	}
	if _, ok := errors.AsType[*socks0.ReplyError](err); ok {
		t.Errorf("the RESOLVE's REP 04 is a *ReplyError in a CONNECT dial error: %v", err)
	}
	// LookupNetIP itself keeps the RESOLVE's reply reachable.
	if _, err := tor.LookupNetIP(t.Context(), "ip", "nx.example"); err == nil {
		t.Error("LookupNetIP: no error")
	} else if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyHostUnreachable {
		t.Errorf("LookupNetIP err %v: no *ReplyError", err)
	}
	// Canceled while the Dialer resolves: still canceled.
	hang := &socks0.Dialer{ProxyAddr: listen(t, answer(nil, nil, true))}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: hang}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)
	_, err = d.DialContext(ctx, "tcp", "nx.example:80")
	if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled || handshakeErrOf(t, err).Stage != socks0.StageResolve {
		t.Errorf("canceled resolve: %v (kind %q)", err, socks0.KindOf(err))
	}
	// A resolver Dialer whose own config is broken (SOCKS4 has no RESOLVE).
	tor4 := &socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t), Config: v4}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Resolver: tor4}
	_, err = d.DialContext(t.Context(), "tcp", "nx.example:80")
	if k, st := socks0.KindOf(err), handshakeErrOf(t, err).Stage; k != socks0.KindDNS || st != socks0.StageResolve {
		t.Errorf("resolver misconfigured: KindOf = %q, stage %q: %v", k, st, err)
	}
}

// Tor's extended errors on CONNECT, with ATYP 0 as Tor sends them, or a full address.
func TestTorExtendedReplies(t *testing.T) {
	for rep := wire.Reply(0xF0); rep <= 0xF7; rep++ {
		for _, resp := range [][]byte{{5, byte(rep), 0, 0, 0, 0, 0, 0, 0, 0}, reply(rep, "0.0.0.0:0")} {
			d := &socks0.Dialer{ProxyAddr: listen(t, answer(resp, nil, false))}
			_, err := d.DialContext(t.Context(), "tcp", "abcdef.onion:80")
			re, ok := errors.AsType[*socks0.ReplyError](err)
			if !ok || re.Reply != rep || socks0.KindOf(err) != socks0.KindReply || errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("rep %#x, ATYP %d: %v", rep, resp[3], err)
				continue
			}
			if s := errors.Unwrap(err).Error(); !strings.HasPrefix(s, "socks reply: tor: onion service") {
				t.Errorf("rep %#x: %q", rep, s)
			}
		}
	}
}
