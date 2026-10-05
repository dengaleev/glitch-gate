package server_test

// The Tor RESOLVE (F0) and RESOLVE_PTR (F1) commands.

import (
	"errors"
	"net"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func isNotFound(err error) bool {
	de, ok := errors.AsType[*net.DNSError](err)
	return ok && de.IsNotFound
}

func TestInteropResolve(t *testing.T) {
	s := withHandler(&server.Mux{Resolve: &server.ResolveHandler{Filter: server.AllowAll}})
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	ips, err := d.LookupNetIP(t.Context(), "ip", "localhost")
	if err != nil || len(ips) != 1 || !ips[0].IsLoopback() {
		t.Fatalf("LookupNetIP: %v, %v", ips, err)
	}
	names, err := d.LookupAddr(t.Context(), "127.0.0.1")
	if err != nil || len(names) != 1 || names[0] == "" {
		t.Fatalf("LookupAddr: %v, %v", names, err)
	}
	if _, err := d.LookupNetIP(t.Context(), "ip", "nonexistent.invalid"); !isNotFound(err) {
		t.Fatalf("invalid name: %v", err)
	}

	s2 := open()
	s2.Handler = &server.Mux{Resolve: &server.ResolveHandler{}}
	d2 := &socks0.Dialer{ProxyAddr: serve(t, s2)}
	if _, err := d2.LookupNetIP(t.Context(), "ip", "localhost"); !isNotFound(err) {
		t.Fatalf("localhost with DefaultFilter: %v", err)
	}
	if _, err := d2.LookupAddr(t.Context(), "127.0.0.1"); !errors.Is(err, socks0.ErrNotAllowed) {
		t.Fatalf("PTR of loopback with DefaultFilter: %v", err)
	}
	for name, s := range map[string]*server.Server{"ConnectHandler": open(), "no handler": {}} {
		d3 := &socks0.Dialer{ProxyAddr: serve(t, s)}
		if _, err := d3.LookupNetIP(t.Context(), "ip", "localhost"); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestResolveEdges(t *testing.T) {
	lookupOnly := fakeDNS{"x.test": "::ffff:8.8.8.8"} // no LookupAddr
	for _, tt := range []struct {
		name string
		h    *server.ResolveHandler
		req  []byte
		rep  wire.Reply
		bnd  string
	}{
		{"F0 literal", &server.ResolveHandler{}, request(wire.CmdTorResolve, "8.8.4.4:0"), 0, "8.8.4.4:0"},
		{"F0 denied literal", &server.ResolveHandler{}, request(wire.CmdTorResolve, "10.1.1.1:0"), 2, ""},
		{"F0 mapped answer", &server.ResolveHandler{Resolver: lookupOnly}, request(wire.CmdTorResolve, "x.test:0"), 0, "8.8.8.8:0"},
		{"F1 without LookupAddr", &server.ResolveHandler{Resolver: lookupOnly}, request(wire.CmdTorResolvePTR, "8.8.8.8:0"), 7, ""},
		{"F1 of a name", &server.ResolveHandler{}, request(wire.CmdTorResolvePTR, "x.test:0"), 4, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := withHandler(tt.h)
			c, errc := serveOne(t, s)
			_, _ = c.Write(cat(greeting(0), tt.req))
			expect(t, c, []byte{5, 0})
			rep, bound, err := wire.ReadReply(c, wire.CmdTorResolve)
			if err != nil || rep != tt.rep || tt.bnd != "" && bound.String() != tt.bnd {
				t.Fatalf("%v %v %v", rep, bound, err)
			}
			_ = result(t, errc)
		})
	}
}
