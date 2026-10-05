package server_test

// Filter and DefaultFilter: no CONNECT reaches an internal address, by any encoding or name.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Every special range, its edges and the embedded-IPv4 forms.
func TestDefaultFilter(t *testing.T) {
	r := &server.Request{LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.114.7"), Port: 1080}}
	check := func(addr, reason string) { // reason "" allowed
		t.Helper()
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			t.Fatal(addr, err)
		}
		network := "tcp6"
		if ap.Addr().Unmap().Is4() {
			network = "tcp4"
		}
		err = server.DefaultFilter(r, network, ap)
		de, denied := errors.AsType[*server.DeniedError](err)
		switch {
		case reason == "" && err != nil:
			t.Errorf("%s: denied: %v", addr, err)
		case reason != "" && (!denied || de.Reason != reason):
			t.Errorf("%s: %v, want %q", addr, err, reason)
		case denied && (!errors.Is(err, server.ErrNotAllowed) || de.Addr.Addr().Is4In6() || de.Addr.Addr().Zone() != "" ||
			err.Error() != "socks target denied: "+reason):
			t.Errorf("%s: %#v", addr, de)
		}
	}
	for _, tt := range []struct{ addr, reason string }{
		{"8.8.8.8:53", ""}, {"1.1.1.1:443", ""}, {"0.0.0.0:80", "unspecified"}, {"0.255.255.255:80", "unspecified"},
		{"10.0.0.1:80", "private"}, {"10.255.255.255:80", "private"}, {"11.0.0.0:80", ""},
		{"100.63.255.255:80", ""}, {"100.64.0.0:80", "cgnat"}, {"100.127.255.255:80", "cgnat"}, {"100.128.0.0:80", ""},
		{"127.0.0.1:80", "loopback"}, {"127.255.255.254:80", "loopback"},
		{"169.254.169.254:80", "link-local"}, {"169.254.0.1:80", "link-local"},
		{"172.15.255.255:80", ""}, {"172.16.0.0:80", "private"}, {"172.31.255.255:80", "private"}, {"172.32.0.0:80", ""},
		{"192.0.0.8:80", "reserved"}, {"192.0.2.1:80", "reserved"}, {"192.88.99.1:80", "reserved"}, {"192.168.1.1:80", "private"},
		{"198.18.0.1:80", "reserved"}, {"198.19.255.255:80", "reserved"}, {"198.20.0.0:80", ""},
		{"198.51.100.1:80", "reserved"}, {"203.0.113.1:80", "reserved"},
		{"224.0.0.1:80", "multicast"}, {"239.255.255.250:1900", "multicast"}, {"240.0.0.1:80", "reserved"}, {"255.255.255.255:80", "reserved"},
		{"203.0.114.7:22", "own address"}, {"203.0.114.8:22", ""}, {"8.8.8.8:0", "port 0"}, {"127.0.0.1:0", "port 0"},
		{"168.63.129.15:80", ""}, {"168.63.129.17:80", ""},
		// IPv6 allowlist.
		{"[2606:4700::1111]:443", ""}, {"[2a00:1450::1]:443", ""}, {"[::]:80", "unspecified"}, {"[::1]:80", "loopback"},
		{"[::8.8.8.8]:80", "reserved"},    // IPv4-compatible ::/96
		{"[64:ff9b:1::1]:80", "reserved"}, // local-use NAT64
		{"[100::1]:80", "reserved"},       // discard-only
		{"[5f00::1]:80", "reserved"},      // SRv6 SIDs
		{"[2001::1]:80", "reserved"},      // Teredo
		{"[2001:1ff::1]:80", "reserved"},  // 2001::/23
		{"[2001:200::1]:80", ""},          // just past 2001::/23
		{"[2001:db8::1]:80", "reserved"},  // documentation
		{"[3fff::1]:80", "reserved"},      // documentation (RFC 9637)
		{"[3fff:1000::1]:80", ""},         // past 3fff::/20
		{"[fc00::1]:80", "private"},       // ULA
		{"[fd00:ec2::254]:80", "private"}, // AWS metadata
		{"[fe80::1]:80", "link-local"}, {"[fe80::1%25en0]:80", "link-local"},
		{"[fec0::1]:80", "reserved"}, // site-local
		{"[ff02::1]:80", "multicast"},
		{"[4000::1]:80", "reserved"}, // outside 2000::/3
		{"[::ffff:127.0.0.1]:80", "loopback"}, {"[::ffff:8.8.8.8]:80", ""}, {"[::ffff:169.254.169.254]:80", "link-local"},
		{"[64:ff9b::a00:1]:80", "private"},         // NAT64 10.0.0.1
		{"[64:ff9b::808:808]:80", ""},              // NAT64 8.8.8.8
		{"[64:ff9b::7f00:1]:80", "loopback"},       // NAT64 127.0.0.1
		{"[2002:7f00:1::]:80", "loopback"},         // 6to4 127.0.0.1
		{"[2002:a9fe:a9fe::1]:80", "link-local"},   // 6to4 169.254.169.254
		{"[2002:808:808::1]:80", ""},               // 6to4 8.8.8.8
		{"[::ffff:203.0.114.7]:22", "own address"}, // mapped
	} {
		check(tt.addr, tt.reason)
	}
	// Azure's WireServer, in every encoding.
	for _, s := range []string{"168.63.129.16", "::ffff:168.63.129.16", "64:ff9b::a83f:8110", "2002:a83f:8110::"} {
		for _, p := range []uint16{80, 32526} {
			check(netip.AddrPortFrom(netip.MustParseAddr(s), p).String(), "metadata")
		}
	}
	// More internal addresses, for any reason, with no Request.
	for _, s := range []string{
		"0.1.2.3", "10.1.2.3", "100.64.0.1", "100.100.100.200", // Alibaba metadata
		"169.254.169.253", "169.254.169.123", "169.254.0.23", // AWS/Tencent
		"172.16.0.1", "192.0.0.170", "239.255.255.250",
		"::127.0.0.1", "::ffff:0:7f00:1", // SIIT
		"64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
		"2001:10::1", "2001:20::1", "fd00:ec2::253", "fe80::1%lo0", "ff0e::1",
	} {
		if err := server.DefaultFilter(nil, "tcp", netip.AddrPortFrom(netip.MustParseAddr(s), 80)); err == nil {
			t.Errorf("%s allowed", s)
		}
	}
	// RESOLVE answers have no port.
	if err := server.DefaultFilter(r, "ip4", netip.MustParseAddrPort("8.8.8.8:0")); err != nil {
		t.Error(err)
	}
	if server.DefaultFilter(nil, "tcp4", netip.MustParseAddrPort("8.8.8.8:1")) != nil ||
		server.AllowAll(nil, "tcp4", netip.MustParseAddrPort("127.0.0.1:0")) != nil {
		t.Error("nil request / AllowAll")
	}
	if socks0.KindOf(&server.DeniedError{Reason: "x"}) != socks0.KindDenied || server.ReplyFor(&server.DeniedError{}) != wire.ReplyNotAllowed {
		t.Error("kind / reply")
	}
	t.Run("SelfAddrs", func(t *testing.T) { // denied as "own address" in every encoding
		type verdict struct {
			addr string
			err  error
		}
		got := make(chan verdict, 16)
		s := &server.Server{
			ErrorLog:  quietLog,
			SelfAddrs: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24"), netip.MustParsePrefix("2001:4860:4860::8844/128")},
			Handler: server.HandlerFunc(func(_ context.Context, r *server.Request) error {
				for _, a := range []string{"8.8.4.4", "::ffff:8.8.4.4", "64:ff9b::808:404", "2002:808:404::", "2001:4860:4860::8844", "8.8.8.8", "2001:4860:4860::8888"} {
					got <- verdict{a, server.DefaultFilter(r, "tcp", netip.AddrPortFrom(netip.MustParseAddr(a), 443))}
				}
				close(got)
				_, err := r.Reply(wire.ReplyNotAllowed, wire.Addr{})
				return err
			}),
		}
		rawReply(t, serve(t, s), request(wire.CmdConnect, "192.0.2.1:80"))
		for v := range got {
			de, denied := errors.AsType[*server.DeniedError](v.err)
			want := v.addr != "8.8.8.8" && v.addr != "2001:4860:4860::8888"
			if denied != want || denied && de.Reason != "own address" {
				t.Errorf("%s: %v, want denied %v", v.addr, v.err, want)
			}
		}
	})
}

func TestFilterControl(t *testing.T) {
	var f server.Filter
	ctl := f.Control(&server.Request{})
	if err := ctl(context.Background(), "tcp4", "127.0.0.1:80", nil); !errors.Is(err, server.ErrNotAllowed) {
		t.Error(err)
	}
	if err := ctl(context.Background(), "tcp4", "8.8.8.8:80", nil); err != nil {
		t.Error(err)
	}
	if err := ctl(context.Background(), "tcp4", "garbage", nil); !errors.Is(err, server.ErrNotAllowed) {
		t.Errorf("fail closed: %v", err)
	}
	f = server.AllowAll
	if err := f.Control(nil)(context.Background(), "tcp6", "[::1]:80", nil); err != nil {
		t.Error(err)
	}
}

type recordFilter struct {
	mu   sync.Mutex
	seen []netip.AddrPort
	f    server.Filter
}

func (r *recordFilter) filter(req *server.Request, network string, a netip.AddrPort) error {
	r.mu.Lock()
	r.seen = append(r.seen, a)
	r.mu.Unlock()
	return r.f(req, network, a)
}

// No CONNECT reaches loopback: a name resolving to an internal IP is denied at connect time, after
// the Filter saw it, and replied 04 (no DNS oracle); no numeric or odd name form succeeds; every
// literal encoding is replied 02.
func TestSSRFInternalTargets(t *testing.T) {
	trap := listenLoopback(t)
	trapped := countAccepts(t, trap)
	port := uint16(trap.Addr().(*net.TCPAddr).Port)
	res := dnsServer(t, map[string][]string{"evil.test": {"127.0.0.1"}, "meta.test": {"169.254.169.254"}, "v6.test": {"::1"}})
	rec := &recordFilter{f: server.DefaultFilter}
	s := withHandler(&server.ConnectHandler{Dialer: &net.Dialer{Resolver: res}, Filter: rec.filter})
	viaDNS := serve(t, s)
	zero := serve(t, &server.Server{ErrorLog: quietLog}) // DefaultFilter, the system resolver
	for _, name := range []string{"evil.test", "meta.test", "v6.test"} {
		if got := rawReply(t, viaDNS, rawRequest(wire.CmdConnect, name, port)); len(got) < 4 || got[3] != byte(wire.ReplyHostUnreachable) {
			t.Errorf("%s: %x, want REP 04", name, got)
		}
	}
	rec.mu.Lock()
	if len(rec.seen) != 3 {
		t.Errorf("filter saw %v", rec.seen)
	}
	rec.mu.Unlock()
	for _, name := range []string{
		"127.1", "127.0.1", "0x7f.1", "0x7f000001", "2130706433", "017700000001", "0177.0.0.1", "127.000.000.001",
		"127.0.0.1.", "localhost", "localhost.", "LOCALHOST", "localhost.localdomain", "ip6-localhost",
		"0", "0.0.0.0", "::1", "::ffff:127.0.0.1", "[::1]", "127.0.0.1%lo0", "::ffff:7f00:1", "0:0:0:0:0:ffff:7f00:1",
		"127.0.0.1\x00.example.com", "127.0.0.1 ", " 127.0.0.1", "127.0.0.1\t",
	} {
		// Some forms resolve to a public IP ("0177.0.0.1" on macOS): no reply is fine.
		if got := rawReply(t, zero, rawRequest(wire.CmdConnect, name, port)); len(got) >= 4 && got[3] == 0 {
			t.Errorf("%q: reply %x", name, got)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "::1", "::"} {
		for _, proxy := range []string{viaDNS, zero} {
			if got := rawReply(t, proxy, request(wire.CmdConnect, netip.AddrPortFrom(netip.MustParseAddr(ip), port).String())); len(got) < 4 || got[3] != byte(wire.ReplyNotAllowed) {
				t.Errorf("%s: %x", ip, got)
			}
		}
	}
	if n := trapped.Load(); n != 0 {
		t.Fatalf("loopback target accepted %d conns", n)
	}
}

func TestSSRFHappyEyeballs(t *testing.T) {
	if !hasIPv6() {
		t.Skip("no IPv6 loopback")
	}
	target := echoTCP(t, "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(target)
	trap, err := net.Listen("tcp", "[::1]:"+port)
	if err != nil {
		t.Skip(err)
	}
	trapped := countAccepts(t, trap)
	res := dnsServer(t, map[string][]string{"mixed.test": {"127.0.0.1", "::1"}})
	deny6 := func(r *server.Request, network string, a netip.AddrPort) error {
		if a.Addr().Is6() {
			return &server.DeniedError{Addr: a, Reason: "test"}
		}
		return nil
	}
	s := withHandler(&server.ConnectHandler{Dialer: &net.Dialer{Resolver: res}, Filter: deny6})
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	for range 5 {
		c, err := d.DialContext(t.Context(), "tcp", "mixed.test:"+port)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, []byte("he"))
		c.Close()
	}
	if trapped.Load() != 0 {
		t.Fatal("connected to the denied IPv6 address")
	}
}

// A target that is this host by another address (the other loopback family) is denied.
func TestSSRFSelfConnect(t *testing.T) {
	if !hasIPv6() {
		t.Skip("no IPv6 loopback")
	}
	// Loopback stands in for an own public address unknown to DefaultFilter.
	loopOK := func(r *server.Request, network string, a netip.AddrPort) error {
		if err := server.DefaultFilter(r, network, a); err != nil {
			if de, _ := errors.AsType[*server.DeniedError](err); de.Reason != "loopback" {
				return err
			}
		}
		return nil
	}
	target6 := echoTCP(t, "[::1]:0")
	s := withHandler(&server.ConnectHandler{Filter: loopOK})
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	_, err := d.DialContext(t.Context(), "tcp", target6)
	if !errors.Is(err, socks0.ErrNotAllowed) {
		t.Fatalf("self-connect via ::1: %v", err)
	}
	c, err := (&socks0.Dialer{ProxyAddr: serve(t, open())}).DialContext(t.Context(), "tcp", target6)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, []byte("ok"))
	c.Close()
}

// portScan CONNECTs through proxy to an open and a closed port of targetIP, served at listenIP: a
// proxy denying targetIP replies the same to both and the open one accepts nothing.
func portScan(t *testing.T, proxy, listenIP, targetIP string) {
	t.Helper()
	svc := listen(t, net.JoinHostPort(listenIP, "0")) // e.g. Redis, firewalled from outside
	accepted := countAccepts(t, svc)
	closedLn := listen(t, net.JoinHostPort(listenIP, "0"))
	closedLn.Close()
	reply := func(ln net.Listener) wire.Reply {
		_, rep, _ := ask(t, proxy, request(wire.CmdConnect, net.JoinHostPort(targetIP, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))))
		return rep
	}
	repOpen, repClosed := reply(svc), reply(closedLn)
	time.Sleep(100 * time.Millisecond)
	if repOpen != wire.ReplyNotAllowed || repClosed != wire.ReplyNotAllowed || accepted.Load() != 0 {
		t.Fatalf("%v: open port → %v, closed → %v, service accepted %d; want 02, 02, 0", targetIP, repOpen, repClosed, accepted.Load())
	}
}

// No port-scan oracle on the proxy's other addresses: refused before connecting.
func TestOwnHostNoPortScanOracle(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	var ip netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			ip = p.Addr()
			break
		}
	}
	if !ip.IsValid() {
		t.Skip("no non-loopback IPv4 address")
	}
	// ownOnly is DefaultFilter's own-address rule alone, so a private IP can stand in for a public one.
	ownOnly := func(r *server.Request, _ string, a netip.AddrPort) error {
		if ta, ok := r.LocalAddr.(*net.TCPAddr); ok && ta.AddrPort().Addr().Unmap() == a.Addr() {
			return &server.DeniedError{Addr: a, Reason: "own address"}
		}
		return nil
	}
	portScan(t, serve(t, &server.Server{ErrorLog: quietLog, Handler: &server.ConnectHandler{Filter: ownOnly}}), ip.String(), ip.String())
}
