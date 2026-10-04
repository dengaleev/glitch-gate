package server

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestVerify(t *testing.T) {
	long := strings.Repeat("x", 300)
	a := UserPass{Users: map[string]string{"u": "p", "empty": "", "long": long, "max": long[:255]}}
	for _, tt := range []struct {
		user, pass string
		ok         bool
	}{
		{"u", "p", true}, {"u", "P", false}, {"u", "", false}, {"u", "p\x00", false},
		{"nobody", "p", false}, {"nobody", "", false},
		{"empty", "", true}, {"empty", "\x00", false},
		{"long", long[:255], false}, // stored over 255 bytes can never match
		{"max", long[:255], true},
	} {
		if got := a.verify([]byte(tt.user), []byte(tt.pass)); got != tt.ok {
			t.Errorf("%s/%q: %v", tt.user, tt.pass, got)
		}
	}
	if digest("") == digest("\x00") || digest("ab") != digest([]byte("ab")) {
		t.Error("digest")
	}
}

// Wrong password, unknown user and long passwords must cost the same.
func BenchmarkVerify(b *testing.B) {
	a := UserPass{Users: map[string]string{"u": "p", "long": strings.Repeat("x", 255)}}
	for _, c := range [][2]string{{"u", "wrong"}, {"nobody", "p"}, {"long", strings.Repeat("y", 255)}, {"u", "p"}} {
		b.Run(c[0]+"/"+c[1][:min(len(c[1]), 5)], func(b *testing.B) {
			user, pass := []byte(c[0]), []byte(c[1])
			for b.Loop() {
				a.verify(user, pass)
			}
		})
	}
}

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

func mustAddr(s string) wire.Addr {
	a, err := wire.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
