package server_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Every special range, its edges and the embedded-IPv4 forms.
func TestDefaultFilter(t *testing.T) {
	r := &server.Request{LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.114.7"), Port: 1080}}
	for _, tt := range []struct {
		addr   string
		reason string // "" allowed
	}{
		{"8.8.8.8:53", ""},
		{"1.1.1.1:443", ""},
		{"0.0.0.0:80", "unspecified"},
		{"0.255.255.255:80", "unspecified"},
		{"10.0.0.1:80", "private"},
		{"10.255.255.255:80", "private"},
		{"11.0.0.0:80", ""},
		{"100.63.255.255:80", ""},
		{"100.64.0.0:80", "cgnat"},
		{"100.127.255.255:80", "cgnat"},
		{"100.128.0.0:80", ""},
		{"127.0.0.1:80", "loopback"},
		{"127.255.255.254:80", "loopback"},
		{"169.254.169.254:80", "link-local"},
		{"169.254.0.1:80", "link-local"},
		{"172.15.255.255:80", ""},
		{"172.16.0.0:80", "private"},
		{"172.31.255.255:80", "private"},
		{"172.32.0.0:80", ""},
		{"192.0.0.8:80", "reserved"},
		{"192.0.2.1:80", "reserved"},
		{"192.88.99.1:80", "reserved"},
		{"192.168.1.1:80", "private"},
		{"198.18.0.1:80", "reserved"},
		{"198.19.255.255:80", "reserved"},
		{"198.20.0.0:80", ""},
		{"198.51.100.1:80", "reserved"},
		{"203.0.113.1:80", "reserved"},
		{"224.0.0.1:80", "multicast"},
		{"239.255.255.250:1900", "multicast"},
		{"240.0.0.1:80", "reserved"},
		{"255.255.255.255:80", "reserved"},
		{"203.0.114.7:22", "own address"},
		{"203.0.114.8:22", ""},
		{"8.8.8.8:0", "port 0"},
		{"127.0.0.1:0", "port 0"},
		// IPv6 allowlist.
		{"[2606:4700::1111]:443", ""},
		{"[2a00:1450::1]:443", ""},
		{"[::]:80", "unspecified"},
		{"[::1]:80", "loopback"},
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
		{"[fe80::1]:80", "link-local"},
		{"[fe80::1%25en0]:80", "link-local"},
		{"[fec0::1]:80", "reserved"}, // site-local
		{"[ff02::1]:80", "multicast"},
		{"[4000::1]:80", "reserved"}, // outside 2000::/3
		{"[::ffff:127.0.0.1]:80", "loopback"},
		{"[::ffff:8.8.8.8]:80", ""},
		{"[::ffff:169.254.169.254]:80", "link-local"},
		{"[64:ff9b::a00:1]:80", "private"},         // NAT64 10.0.0.1
		{"[64:ff9b::808:808]:80", ""},              // NAT64 8.8.8.8
		{"[64:ff9b::7f00:1]:80", "loopback"},       // NAT64 127.0.0.1
		{"[2002:7f00:1::]:80", "loopback"},         // 6to4 127.0.0.1
		{"[2002:a9fe:a9fe::1]:80", "link-local"},   // 6to4 169.254.169.254
		{"[2002:808:808::1]:80", ""},               // 6to4 8.8.8.8
		{"[::ffff:203.0.114.7]:22", "own address"}, // mapped
	} {
		ap, err := netip.ParseAddrPort(tt.addr)
		if err != nil {
			t.Fatal(tt.addr, err)
		}
		network := "tcp6"
		if ap.Addr().Unmap().Is4() {
			network = "tcp4"
		}
		err = server.DefaultFilter(r, network, ap)
		de, denied := errors.AsType[*server.DeniedError](err)
		switch {
		case tt.reason == "" && err != nil:
			t.Errorf("%s: denied: %v", tt.addr, err)
		case tt.reason != "" && (!denied || de.Reason != tt.reason):
			t.Errorf("%s: %v, want %q", tt.addr, err, tt.reason)
		case denied && (!errors.Is(err, server.ErrNotAllowed) || de.Addr.Addr().Is4In6() || de.Addr.Addr().Zone() != "" ||
			err.Error() != "socks target denied: "+tt.reason):
			t.Errorf("%s: %#v", tt.addr, de)
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

// A name resolving to a private IP is denied at connect time and replied 04 (no DNS oracle).
func TestSSRFNameToPrivate(t *testing.T) {
	trap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer trap.Close()
	var trapped atomic.Int32
	go func() {
		for {
			c, err := trap.Accept()
			if err != nil {
				return
			}
			trapped.Add(1)
			c.Close()
		}
	}()
	res := dnsServer(t, map[string][]string{"evil.test": {"127.0.0.1"}, "meta.test": {"169.254.169.254"}, "v6.test": {"::1"}})
	rec := &recordFilter{f: server.DefaultFilter}
	s := open()
	s.Handler = &server.ConnectHandler{Dialer: &net.Dialer{Resolver: res}, Filter: rec.filter}
	proxy := serve(t, s)
	_, port, _ := net.SplitHostPort(trap.Addr().String())
	for _, name := range []string{"evil.test", "meta.test", "v6.test"} {
		d := &socks0.Dialer{ProxyAddr: proxy}
		_, err := d.DialContext(t.Context(), "tcp", name+":"+port)
		if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyHostUnreachable {
			t.Errorf("%s: %v, want REP 04", name, err)
		}
	}
	if trapped.Load() != 0 {
		t.Fatal("a denied address was connected to")
	}
	if len(rec.seen) != 3 {
		t.Errorf("filter saw %v", rec.seen)
	}
	_, err = (&socks0.Dialer{ProxyAddr: proxy}).DialContext(t.Context(), "tcp", trap.Addr().String())
	if !errors.Is(err, socks0.ErrNotAllowed) {
		t.Errorf("literal: %v", err)
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
	var trapped atomic.Int32
	go func() {
		for {
			c, err := trap.Accept()
			if err != nil {
				return
			}
			trapped.Add(1)
			c.Close()
		}
	}()
	defer trap.Close()
	res := dnsServer(t, map[string][]string{"mixed.test": {"127.0.0.1", "::1"}})
	deny6 := func(r *server.Request, network string, a netip.AddrPort) error {
		if a.Addr().Is6() {
			return &server.DeniedError{Addr: a, Reason: "test"}
		}
		return nil
	}
	s := open()
	s.Handler = &server.ConnectHandler{Dialer: &net.Dialer{Resolver: res}, Filter: deny6}
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

// S3: a target that is this host by another address (the other loopback family) is denied.
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
	s := open()
	s.Handler = &server.ConnectHandler{Filter: loopOK}
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	_, err := d.DialContext(t.Context(), "tcp", target6)
	if !errors.Is(err, socks0.ErrNotAllowed) {
		t.Fatalf("self-connect via ::1: %v", err)
	}
	s2 := open()
	c, err := (&socks0.Dialer{ProxyAddr: serve(t, s2)}).DialContext(t.Context(), "tcp", target6)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, []byte("ok"))
	c.Close()
}

func TestReplyFor(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want wire.Reply
	}{
		{nil, 0},
		{&socks0.ReplyError{Reply: 0xF6}, 0xF6},
		{&net.OpError{Err: &socks0.ReplyError{Reply: 5}}, 5},
		{&socks0.ReplyError{Reply: 0x5B, Version: 4}, 1},
		{&socks0.ReplyError{Reply: 0x5C, Version: 4}, 2},
		{&socks0.ReplyError{Reply: 0x5D, Version: 4}, 2},
		{&server.DeniedError{}, 2},
		{errors.Join(io.EOF, server.ErrNotAllowed), 2},
		{errors.ErrUnsupported, 7},
		{&net.DNSError{Err: "x"}, 4},
		{context.DeadlineExceeded, 6},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, 6},
		{context.Canceled, 1},
		{io.EOF, 1},
	} {
		if got := server.ReplyFor(tt.err); got != tt.want {
			t.Errorf("ReplyFor(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
	for _, tt := range errnoReplies() {
		if got := server.ReplyFor(&net.OpError{Op: "dial", Err: tt.err}); got != tt.want {
			t.Errorf("ReplyFor(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }
