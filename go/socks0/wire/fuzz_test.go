package wire

import (
	"errors"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Any bytes keep the Parse contract, re-encode canonically and read as they parse.

func addVectorSeeds(f *testing.F, c codec, args ...any) {
	for _, v := range valid() {
		if v.c.stage == c.stage {
			f.Add(append([]any{v.b}, args...)...)
		}
	}
	for _, v := range malformed() {
		if v.c.stage == c.stage {
			f.Add(append([]any{v.b}, args...)...)
		}
	}
}

func FuzzParseGreeting(f *testing.F) {
	addVectorSeeds(f, greeting)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, greeting, b) })
}

func FuzzParseUserPass(f *testing.F) {
	addVectorSeeds(f, userPass)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, userPass, b) })
}

func FuzzParseRequest(f *testing.F) {
	addVectorSeeds(f, request)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, request, b) })
}

func FuzzParseMethodSelection(f *testing.F) {
	addVectorSeeds(f, selection)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, selection, b) })
}

func FuzzParseUserPassStatus(f *testing.F) {
	addVectorSeeds(f, status)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, status, b) })
}

func FuzzParseReply(f *testing.F) {
	addVectorSeeds(f, replyConnect, byte(CmdConnect))
	addVectorSeeds(f, replyConnect, byte(CmdTorResolve))
	f.Fuzz(func(t *testing.T, b []byte, cmd byte) { checkRobust(t, reply(Command(cmd)), b) })
}

func FuzzParseUDPHeader(f *testing.F) {
	addVectorSeeds(f, udp)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, udp, b) })
}

func FuzzParseRequest4(f *testing.F) {
	addVectorSeeds(f, request4)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, request4, b) })
}

func FuzzParseReply4(f *testing.F) {
	addVectorSeeds(f, reply4)
	f.Fuzz(func(t *testing.T, b []byte) { checkRobust(t, reply4, b) })
}

func checkRobust(t *testing.T, c codec, b []byte) {
	v, n, err := c.parse(b)
	switch {
	case err == nil:
		if n <= 0 || n > len(b) {
			t.Fatalf("n = %d of %d bytes", n, len(b))
		}
		for i := range n {
			if _, ni, err := c.parse(b[:i]); err != ErrIncomplete || ni <= i || ni > n {
				t.Fatalf("prefix %d: n = %d, %v; want ErrIncomplete, %d < n ≤ %d", i, ni, err, i, n)
			}
		}
		enc, err := c.encode(nil, v)
		if hasZeroAddr(v) || inSOCKS4aRange(v) {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("encode(%v) = %v; want ErrInvalid (zero Addr)", v, err)
			}
		} else if want := canonical(c.stage, b[:n]); err != nil || string(enc) != string(want) {
			t.Fatalf("encode(%v) = % x, %v; want % x", v, enc, err, want)
		}
	case err == ErrIncomplete:
		if n <= len(b) {
			t.Fatalf("ErrIncomplete with n = %d ≤ %d", n, len(b))
		}
	default:
		pe, ok := errors.AsType[*ProtocolError](err)
		if !ok || n != 0 || pe.Stage != c.stage || pe.Field == "" || pe.Err != nil {
			t.Fatalf("parse = %d, %#v; want 0, a *ProtocolError of stage %q", n, err, c.stage)
		}
		if _, _, err2 := c.parse(append(slices.Clip(b), make([]byte, 300)...)); !reflect.DeepEqual(err2, err) {
			t.Fatalf("error changed with more bytes: %v, then %v", err, err2)
		}
	}
	if c.read == nil {
		return
	}
	rv, consumed, rerr := readBytes(c, b)
	switch {
	case err == nil && (rerr != nil || consumed != n):
		t.Fatalf("read = %v, consumed %d; want nil, %d", rerr, consumed, n)
	case err == ErrIncomplete && !reflect.DeepEqual(rerr, &ProtocolError{Stage: c.stage, Err: io.ErrUnexpectedEOF}):
		t.Fatalf("read of a prefix = %v; want truncation", rerr)
	case err != nil && err != ErrIncomplete && !reflect.DeepEqual(rerr, err):
		t.Fatalf("read = %v; parse = %v", rerr, err)
	case !reflect.DeepEqual(rv, v):
		t.Fatalf("read = %v; parse = %v", rv, v)
	}
}

// inSOCKS4aRange: DSTIP 0.0.0.0 parses but cannot be encoded.
func inSOCKS4aRange(v any) bool {
	r, ok := v.(request4V)
	ip := r.addr.IP().As16()
	return ok && r.addr.IP().Is4() && ip[12] == 0 && ip[13] == 0 && ip[14] == 0
}

func hasZeroAddr(v any) bool {
	r, ok := v.(repAddr)
	return ok && r.addr == Addr{}
}

// canonical returns the re-encoding of b: RSV zero, IPv4-mapped IPv6 as IPv4.
func canonical(stage string, b []byte) []byte {
	b = slices.Clone(b)
	switch stage {
	case StageRequest, StageReply:
		b[2] = 0
	case StageUDPHeader:
		b[0], b[1] = 0, 0
	case StageRequest4:
		if b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] != 0 {
			b[7] = 1
		}
		return b
	default:
		return b
	}
	if ATYP(b[3]) == ATYPIPv6 && netip.AddrFrom16([16]byte(b[4:20])).Is4In6() {
		return msg(b[:3], 1, b[16:22])
	}
	return b
}

// Round trip: encoded values parse and read back.

func FuzzRoundTripGreeting(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{})
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, raw []byte) {
		methods := make([]Method, len(raw))
		for i, m := range raw {
			methods[i] = Method(m)
		}
		roundTrip(t, greeting, methods, len(raw) >= 1 && len(raw) <= 255)
	})
}

func FuzzRoundTripUserPass(f *testing.F) {
	f.Add("user", "pass")
	f.Add("", "")
	f.Add(long+"x", "")
	f.Fuzz(func(t *testing.T, user, pass string) {
		roundTrip(t, userPass, userPassV{user, pass}, len(user) <= 255 && len(pass) <= 255)
	})
}

func FuzzRoundTripMethodSelection(f *testing.F) {
	f.Add(byte(0))
	f.Fuzz(func(t *testing.T, m byte) { roundTrip(t, selection, Method(m), true) })
}

func FuzzRoundTripUserPassStatus(f *testing.F) {
	f.Add(byte(0))
	f.Fuzz(func(t *testing.T, s byte) { roundTrip(t, status, s, true) })
}

func addAddrSeeds(f *testing.F, b byte) {
	for kind := range byte(4) {
		f.Add(b, kind, []byte{192, 0, 2, 1}, "example.com", uint16(80))
	}
	f.Add(b, byte(1), netip.MustParseAddr("::ffff:192.0.2.1").AsSlice(), "", uint16(1))
	f.Add(b, byte(3), []byte{}, "[2001:db8::1]:443", uint16(0))
	f.Add(b, byte(2), []byte{}, "", uint16(0))
}

func FuzzRoundTripRequest(f *testing.F) {
	addAddrSeeds(f, byte(CmdConnect))
	f.Fuzz(func(t *testing.T, cmd, kind byte, ip []byte, name string, port uint16) {
		a := fuzzAddr(kind, ip, name, port)
		roundTrip(t, request, cmdAddr{Command(cmd), a}, a.IsValid())
	})
}

func FuzzRoundTripReply(f *testing.F) {
	addAddrSeeds(f, byte(ReplySucceeded))
	f.Fuzz(func(t *testing.T, rep, kind byte, ip []byte, name string, port uint16) {
		a := fuzzAddr(kind, ip, name, port)
		for _, cmd := range []Command{CmdConnect, CmdTorResolve} {
			roundTrip(t, reply(cmd), repAddr{Reply(rep), a}, a.IsValid())
		}
	})
}

func FuzzRoundTripUDPHeader(f *testing.F) {
	addAddrSeeds(f, 0)
	f.Fuzz(func(t *testing.T, frag, kind byte, ip []byte, name string, port uint16) {
		a := fuzzAddr(kind, ip, name, port)
		roundTrip(t, udp, fragAddr{frag, a}, a.IsValid())
		if b, _ := AppendUDPHeader(nil, frag, a); UDPHeaderLen(a) != len(b) {
			t.Fatalf("UDPHeaderLen(%v) = %d, header is %d bytes", a, UDPHeaderLen(a), len(b))
		}
	})
}

func FuzzRoundTripRequest4(f *testing.F) {
	for kind := range byte(4) {
		f.Add(byte(CmdConnect), kind, []byte{192, 0, 2, 1}, "example.com", "user", uint16(80))
	}
	f.Add(byte(CmdBind), byte(0), []byte{0, 0, 0, 9}, "", "", uint16(1))
	f.Add(byte(CmdConnect), byte(2), []byte{}, "a\x00b", "u\x00", uint16(1))
	f.Fuzz(func(t *testing.T, cmd, kind byte, ip []byte, name, user string, port uint16) {
		a := fuzzAddr(kind, ip, name, port)
		ok := a.IsValid() && !a.IP().Is6() && !inSOCKS4aRange(request4V{addr: a}) && len(user) <= 255 &&
			!strings.Contains(user, "\x00") && !strings.Contains(a.Name(), "\x00")
		roundTrip(t, request4, request4V{Command(cmd), a, user}, ok)
	})
}

func FuzzRoundTripReply4(f *testing.F) {
	f.Add(byte(Reply4Granted), []byte{0, 0, 0, 0}, uint16(0))
	f.Add(byte(Reply4Rejected), []byte{192, 0, 2, 1}, uint16(1080))
	f.Fuzz(func(t *testing.T, rep byte, ip []byte, port uint16) {
		if len(ip) < 4 {
			return
		}
		a := AddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip)), port))
		roundTrip(t, reply4, repAddr{Reply(rep), a}, true)
	})
}

// fuzzAddr returns the zero Addr if the inputs do not fit.
func fuzzAddr(kind byte, ip []byte, name string, port uint16) Addr {
	switch {
	case kind%4 == 0 && len(ip) >= 4:
		return AddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip)), port))
	case kind%4 == 1 && len(ip) >= 16:
		return AddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom16([16]byte(ip)), port))
	case kind%4 == 2 && len(name) >= 1 && len(name) <= 255:
		return Addr{name: name, port: port}
	case kind%4 == 3:
		a, _ := ParseAddr(name)
		return a
	}
	return Addr{}
}

func roundTrip(t *testing.T, c codec, v any, ok bool) {
	dst := []byte{0xEE}
	b, err := c.encode(dst, v)
	if !ok {
		if !errors.Is(err, ErrInvalid) || !same(b, dst) {
			t.Fatalf("encode(%v) = % x, %v; want dst unchanged, ErrInvalid", v, b, err)
		}
		return
	}
	if err != nil || b[0] != 0xEE {
		t.Fatalf("encode(%v) = % x, %v", v, b, err)
	}
	b = b[1:]
	checkParse(t, c, b, v)
	if c.read != nil {
		if rv, consumed, err := readBytes(c, append(b, 0xAA)); err != nil || consumed != len(b) || !reflect.DeepEqual(rv, v) {
			t.Fatalf("read(% x) = %v, %d, %v; want %v, %d", b, rv, consumed, err, v, len(b))
		}
	}
}

func FuzzParseAddr(f *testing.F) {
	for _, s := range []string{"192.0.2.1:1080", "[2001:db8::1]:443", "[::ffff:1.2.3.4]:0", "example.com:80", "[fe80::1%eth0]:1", "a:65536", ":0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAddr(s)
		if err != nil {
			if !isAddrError(err) || a != (Addr{}) {
				t.Fatalf("ParseAddr(%q) = %v, %#v", s, a, err)
			}
			return
		}
		if !a.IsValid() || a.IP().Zone() != "" || a.IP().Is4In6() || len(a.Name()) > 255 {
			t.Fatalf("ParseAddr(%q) = %#v", s, a)
		}
		if b, err := ParseAddr(a.String()); err != nil || b != a {
			t.Fatalf("ParseAddr(%q) = %v; ParseAddr(%q) = %v, %v", s, a, a.String(), b, err)
		}
		bin, err := a.AppendBinary(nil)
		if _, got, _, err2 := ParseRequest(msg(5, 1, 0, bin)); err != nil || err2 != nil || got != a {
			t.Fatalf("AppendBinary(%v) = % x, %v; parsed back as %v, %v", a, bin, err, got, err2)
		}
	})
}
