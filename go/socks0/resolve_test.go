package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type cmdAddr struct {
	cmd  wire.Command
	addr wire.Addr
}

// torProxy answers one request with reply and closes, as Tor does for RESOLVE.
type torProxy struct {
	reply []byte
	got   chan cmdAddr
	hang  bool // never reply
}

func (p torProxy) serve(c net.Conn) {
	methods, err := wire.ReadGreeting(c)
	if err != nil {
		return
	}
	c.Write(wire.AppendMethodSelection(nil, methods[0]))
	if methods[0] == wire.MethodUserPass {
		if _, _, err := wire.ReadUserPass(c); err != nil {
			return
		}
		c.Write(wire.AppendUserPassStatus(nil, 0))
	}
	cmd, addr, err := wire.ReadRequest(c)
	if err != nil {
		return
	}
	if p.got != nil {
		p.got <- cmdAddr{cmd, addr}
	}
	if p.hang {
		io.Copy(io.Discard, c)
		return
	}
	c.Write(p.reply)
}

func noDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		t.Error("dialed the proxy")
		return nil, errTest
	}
}

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
				got := make(chan cmdAddr, 1)
				auth := socks0.UserPass{Username: "isolation", Password: "x"}
				d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: tt.reply, got: got}.serve), Config: &socks0.Config{Mode: mode, Auth: auth}}
				ips, err := d.LookupNetIP(t.Context(), tt.network, "example.com")
				if r := <-got; r != (cmdAddr{wire.CmdTorResolve, mustAddr("example.com:0")}) {
					t.Errorf("request %v", r)
				}
				if tt.want == "" {
					de, ok := err.(*net.DNSError)
					if !ok || !de.IsNotFound || de.Name != "example.com" || de.Server != d.ProxyAddr {
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

func TestLookupErrors(t *testing.T) {
	refused := []byte{5, 4, 0, 0, 0, 0, 0, 0, 0, 0} // REP 04, ATYP 0
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
			d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: tt.reply}.serve)}
			_, err := d.LookupHost(t.Context(), "example.com")
			de, ok := err.(*net.DNSError)
			if !ok || de.IsNotFound != tt.notFound || de.Name != "example.com" || de.Server != d.ProxyAddr || de.IsTimeout {
				t.Fatalf("err = %#v", err)
			}
			oe, ok := de.UnwrapErr.(*net.OpError)
			if !ok || oe.Op != "socks resolve" || socks0.KindOf(err) != tt.kind || tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v; kind %q", err, socks0.KindOf(err))
			}
			if tt.notFound && de.Err != "no such host" {
				t.Errorf("Err %q", de.Err)
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{hang: true}.serve)}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		_, err := d.LookupNetIP(ctx, "ip", "example.com")
		if de, ok := err.(*net.DNSError); !ok || !de.IsTimeout || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %#v", err)
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
				d.Config = &socks0.Config{Version: 4}
				_, err := d.LookupHost(t.Context(), "example.com")
				return err
			},
			func(d *socks0.Dialer) error {
				d.Config = &socks0.Config{Version: 4}
				_, err := d.LookupAddr(t.Context(), "192.0.2.1")
				return err
			},
		} {
			d := &socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t)}
			err := f(d)
			if _, ok := err.(*net.DNSError); !ok || socks0.KindOf(err) != socks0.KindConfig {
				t.Errorf("err = %#v", err)
			}
		}
		var d *socks0.Dialer
		if _, err := d.LookupHost(t.Context(), "example.com"); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("nil Dialer: %v", err)
		}
	})
}

func TestLookupAddr(t *testing.T) {
	got := make(chan cmdAddr, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: reply(0, "host.example:0"), got: got}.serve)}
	names, err := d.LookupAddr(t.Context(), "192.0.2.1")
	if err != nil || !slices.Equal(names, []string{"host.example"}) {
		t.Fatalf("LookupAddr = %v, %v", names, err)
	}
	if r := <-got; r != (cmdAddr{wire.CmdTorResolvePTR, mustAddr("192.0.2.1:0")}) {
		t.Errorf("request %v", r)
	}
	d = &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: reply(0, "192.0.2.1:0")}.serve)}
	if _, err := d.LookupAddr(t.Context(), "192.0.2.1"); socks0.KindOf(err) != socks0.KindProtocol {
		t.Errorf("PTR answered with an IP: %v", err)
	}
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:9050", ProxyDial: noDial(t)}
	if _, err := d.LookupAddr(t.Context(), "host.example"); err == nil || err.(*net.DNSError).Err != "unrecognized address" {
		t.Errorf("LookupAddr of a name: %v", err)
	}
}

func TestDialerAsResolver(t *testing.T) {
	var _ socks0.Resolver = (*socks0.Dialer)(nil)
	tor := &socks0.Dialer{ProxyAddr: listen(t, torProxy{reply: reply(0, "192.0.2.80:0")}.serve)}
	got := make(chan request, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve), Resolver: tor}
	c, err := d.DialContext(t.Context(), "tcp4", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if r := <-got; r.target != mustAddr("192.0.2.80:80") {
		t.Errorf("target %v", r.target)
	}
}
