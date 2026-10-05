package wire

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// msg concatenates its parts; ints and runes are one byte each.
func msg(parts ...any) []byte {
	var b []byte
	for _, p := range parts {
		switch p := p.(type) {
		case int:
			b = append(b, byte(p))
		case rune:
			b = append(b, byte(p))
		case byte:
			b = append(b, p)
		case string:
			b = append(b, p...)
		case []byte:
			b = append(b, p...)
		default:
			panic(p)
		}
	}
	return b
}

func mustAddr(s string) Addr {
	a, err := ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

var (
	v4     = mustAddr("192.0.2.1:1080")
	v6     = mustAddr("[2001:db8::1]:443")
	dom    = mustAddr("example.com:80")
	v4Bin  = msg(1, 192, 0, 2, 1, 0x04, 0x38)
	v6Bin  = msg(4, 0x20, 0x01, 0x0d, 0xb8, make([]byte, 11), 1, 0x01, 0xbb)
	domBin = msg(3, 11, "example.com", 0, 80)
	long   = strings.Repeat("a", 255)
)

func TestParseAddr(t *testing.T) {
	ip := netip.MustParseAddr
	for _, tt := range []struct {
		in   string
		ip   netip.Addr
		name string
		port uint16
	}{
		{"192.0.2.1:1080", ip("192.0.2.1"), "", 1080},
		{"[2001:db8::1]:443", ip("2001:db8::1"), "", 443},
		{"[::ffff:192.0.2.1]:80", ip("192.0.2.1"), "", 80},
		{"[::]:0", ip("::"), "", 0},
		{"example.com:65535", netip.Addr{}, "example.com", 65535},
		{"x.onion:080", netip.Addr{}, "x.onion", 80},
		{"01.2.3.4:1", netip.Addr{}, "01.2.3.4", 1},
		{"1.2.3.4.5:1", netip.Addr{}, "1.2.3.4.5", 1},
		{"1.2.3.4%eth0:1", netip.Addr{}, "1.2.3.4%eth0", 1},
		{long + ":1", netip.Addr{}, long, 1},
	} {
		a, err := ParseAddr(tt.in)
		if err != nil || a.IP() != tt.ip || a.Name() != tt.name || a.Port() != tt.port {
			t.Errorf("ParseAddr(%q) = %v %v %q %d, %v", tt.in, a, a.IP(), a.Name(), a.Port(), err)
		}
		if !a.IsValid() || a.IsName() != (tt.name != "") {
			t.Errorf("ParseAddr(%q): IsValid %v IsName %v", tt.in, a.IsValid(), a.IsName())
		}
	}
	for _, in := range []string{
		"", "example.com", "example.com:", ":80", "a:65536", "a:-1", "a:+1", "a:0x10", "a:http", "a: 1",
		"::1:80", "a:1:2", "[fe80::1%eth0]:80", "[1.2.3.4]:80", "[example.com]:80", "[::1]", long + "a:1",
	} {
		if a, err := ParseAddr(in); !isAddrError(err) || a != (Addr{}) {
			t.Errorf("ParseAddr(%q) = %v, %v; want zero Addr and *net.AddrError", in, a, err)
		}
	}
}

func isAddrError(err error) bool {
	_, ok := errors.AsType[*net.AddrError](err)
	return ok
}

func TestAddrFromAddrPort(t *testing.T) {
	ap := netip.MustParseAddrPort
	for _, tt := range []struct {
		in   netip.AddrPort
		want Addr
	}{
		{ap("192.0.2.1:1080"), v4},
		{ap("[2001:db8::1]:443"), v6},
		{ap("[::ffff:192.0.2.1]:1080"), v4},
		{ap("[2001:db8::1%eth0]:443"), v6},
		{netip.AddrPort{}, Addr{}},
		{netip.AddrPortFrom(netip.Addr{}, 80), Addr{}},
	} {
		if got := AddrFromAddrPort(tt.in); got != tt.want {
			t.Errorf("AddrFromAddrPort(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestAddrMethods(t *testing.T) {
	for _, tt := range []struct {
		a    Addr
		atyp ATYP
		str  string
		bin  []byte
	}{
		{v4, ATYPIPv4, "192.0.2.1:1080", v4Bin},
		{v6, ATYPIPv6, "[2001:db8::1]:443", v6Bin},
		{dom, ATYPDomain, "example.com:80", domBin},
		{Addr{name: "a:b", port: 1}, ATYPDomain, "[a:b]:1", msg(3, 3, "a:b", 0, 1)},
		{Addr{}, 0, "invalid Addr", nil},
	} {
		if got := tt.a.ATYP(); got != tt.atyp {
			t.Errorf("%v.ATYP() = %v, want %v", tt.a, got, tt.atyp)
		}
		if got := tt.a.String(); got != tt.str {
			t.Errorf("String() = %q, want %q", got, tt.str)
		}
		if got := tt.a.Network(); got != "socks" {
			t.Errorf("Network() = %q", got)
		}
		dst := []byte{0xEE}
		got, err := tt.a.AppendBinary(dst)
		if tt.bin == nil {
			if !errors.Is(err, ErrInvalid) || !same(got, dst) {
				t.Errorf("%v.AppendBinary = % x, %v; want dst unchanged, ErrInvalid", tt.a, got, err)
			}
			continue
		}
		if want := msg(0xEE, tt.bin); err != nil || string(got) != string(want) {
			t.Errorf("%v.AppendBinary = % x, %v; want % x", tt.a, got, err, want)
		}
	}
}

func same(a, b []byte) bool {
	return len(a) == len(b) && cap(a) == cap(b) && (cap(a) == 0 || &a[:cap(a)][0] == &b[:cap(b)][0])
}
