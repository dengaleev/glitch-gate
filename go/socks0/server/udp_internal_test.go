package server

// The UDP relay's internals: framing, the header cache, name resolution.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// frame writes only the header region and round-trips through the parser.
func FuzzUDPFrame(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, uint16(53), []byte("answer"))
	f.Add(bytes.Repeat([]byte{0xfe}, 16), uint16(0), []byte{})
	f.Fuzz(func(t *testing.T, ip []byte, port uint16, payload []byte) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		from := normalize(netip.AddrPortFrom(addr, port))
		buf := bytes.Repeat([]byte{0xAA}, headroom+len(payload)+8)
		copy(buf[headroom:], payload)
		d := frame(buf, from, len(payload))
		_, src, n, err := wire.ParseUDPHeader(d)
		if err != nil || src != wire.AddrFromAddrPort(from) || !bytes.Equal(d[n:], payload) {
			t.Fatalf("frame %x: %v %v", d, src, err)
		}
		if start := headroom - n; !bytes.Equal(buf[:start], bytes.Repeat([]byte{0xAA}, start)) ||
			!bytes.Equal(buf[headroom+len(payload):], bytes.Repeat([]byte{0xAA}, 8)) {
			t.Fatal("wrote outside the header")
		}
	})
}

// A cached header verdict equals a fresh one.
func FuzzUDPHeader(f *testing.F) {
	h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(netip.MustParseAddrPort("10.0.0.1:53")))
	f.Add(append(h, "q"...))
	n, _ := wire.AppendUDPHeader(nil, 0, mustAddr("a.test:53"))
	f.Add(append(n, "q"...))
	f.Add([]byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 53})
	f.Add([]byte{0, 0, 0, 3, 0})
	f.Fuzz(func(t *testing.T, p []byte) {
		a := &association{
			ctx: context.Background(), r: &Request{}, resolver: stubDNS{}, maxTargets: 4,
			targets: map[netip.AddrPort]error{}, ips: map[netip.Addr]struct{}{}, names: map[string]nameEntry{},
		}
		dst1, hl1, err1 := a.header(p)
		dst2, hl2, err2 := a.header(p)
		if dst1 != dst2 || hl1 != hl2 || (err1 == nil) != (err2 == nil) {
			t.Fatalf("%x: %v %d %v, then %v %d %v", p, dst1, hl1, err1, dst2, hl2, err2)
		}
		if err1 == nil && (hl1 > len(p) || !dst1.Addr().IsValid()) {
			t.Fatalf("%x: %v %d", p, dst1, hl1)
		}
	})
}

type stubDNS struct{}

func (stubDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if strings.HasSuffix(host, ".test") {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// association.resolve: the first allowed IP; else a denial beats a lookup *net.DNSError and any
// other lookup error beats a denial; no answer and no error is not found.
func TestAssociationResolve(t *testing.T) {
	ip := netip.MustParseAddr
	denied, broke := &DeniedError{Reason: "test"}, errors.New("resolver broke")
	dnsErr := &net.DNSError{Err: "server misbehaving", Name: "x.test"}
	deny1 := Filter(func(_ *Request, _ string, a netip.AddrPort) error {
		if a.Addr() == ip("192.0.2.1") {
			return denied
		}
		return nil
	})
	for _, tc := range []struct {
		name   string
		ips    []netip.Addr
		err    error
		wantIP netip.Addr
		want   error
	}{
		{"first allowed", []netip.Addr{ip("192.0.2.1"), ip("::ffff:192.0.2.2"), ip("192.0.2.3")}, nil, ip("192.0.2.2"), nil},
		{"allowed despite an error", []netip.Addr{ip("192.0.2.2")}, broke, ip("192.0.2.2"), nil},
		{"all denied", []netip.Addr{ip("192.0.2.1")}, nil, netip.Addr{}, denied},
		{"denied, DNS error", []netip.Addr{ip("192.0.2.1")}, dnsErr, netip.Addr{}, denied},
		{"denied, other error", []netip.Addr{ip("192.0.2.1")}, broke, netip.Addr{}, broke},
		{"DNS error", nil, dnsErr, netip.Addr{}, dnsErr},
		{"no answer", nil, nil, netip.Addr{}, nil},
	} {
		a := &association{ctx: context.Background(), r: &Request{}, filter: deny1, resolver: resolverFunc(func() ([]netip.Addr, error) { return tc.ips, tc.err })}
		e := a.resolve("x.test", 53)
		switch {
		case e.ip != tc.wantIP:
			t.Errorf("%s: ip %v, want %v", tc.name, e.ip, tc.wantIP)
		case tc.want != nil && e.err != tc.want:
			t.Errorf("%s: err %v, want %v", tc.name, e.err, tc.want)
		case tc.want == nil && tc.wantIP.IsValid() != (e.err == nil):
			t.Errorf("%s: err %v", tc.name, e.err)
		}
		if de, ok := e.err.(*net.DNSError); tc.name == "no answer" && (!ok || !de.IsNotFound || de.Name != "x.test") {
			t.Errorf("no answer: %#v", e.err)
		}
	}
}
