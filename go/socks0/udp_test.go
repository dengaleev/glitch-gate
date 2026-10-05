package socks0_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	_ net.Conn       = (*socks0.UDPConn)(nil)
	_ net.PacketConn = (*socks0.UDPConn)(nil)
	_ syscall.Conn   = (*socks0.UDPConn)(nil)
)

func unspec4(ap netip.AddrPort) wire.Addr {
	return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port()))
}

func unspec6(ap netip.AddrPort) wire.Addr {
	return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), ap.Port()))
}

func TestUDPDial(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	for _, mode := range modes {
		for _, target := range []string{echoAP.String(), fmt.Sprintf("localhost:%d", echoAP.Port())} {
			t.Run(mode.String()+"/"+target, func(t *testing.T) {
				got := make(chan wire.Addr, 1)
				raw := make(chan []byte, 1)
				conns := make(chan *recConn, 1)
				d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{got: got, raw: raw}.serve), ProxyDial: recDial(conns), Config: &socks0.Config{Mode: mode}}
				c := mustDial(t, d, "udp", target)
				uc := c.(*socks0.UDPConn)
				if s := roundTrip(t, c, "ping"); s != "ping" {
					t.Fatalf("echo %q", s)
				}
				if dst := <-got; dst != mustAddr("0.0.0.0:0") {
					t.Errorf("DST %v", dst)
				}
				if d0, want := <-raw, wire.UDPHeaderLen(mustAddr(target))+4; len(d0) != want {
					t.Errorf("datagram of %d bytes, want %d", len(d0), want)
				}
				if writes, _ := (<-conns).snapshot(); len(writes) != max(map[socks0.Mode]int{socks0.ModeSequential: 2}[mode], 1) {
					t.Errorf("%d handshake writes", len(writes))
				}
				if ra := c.RemoteAddr(); ra.String() != target {
					t.Errorf("RemoteAddr %v", ra)
				}
				if _, ok := c.RemoteAddr().(*net.UDPAddr); ok == mustAddr(target).IsName() {
					t.Errorf("RemoteAddr is %T", c.RemoteAddr())
				}
				if uc.RelayAddr().String() != uc.BoundAddr().String() || uc.LocalAddr() == nil {
					t.Errorf("RelayAddr %v, BoundAddr %v, LocalAddr %v", uc.RelayAddr(), uc.BoundAddr(), uc.LocalAddr())
				}
				if uc.Err() != nil {
					t.Error(uc.Err())
				}
			})
		}
	}
}

func TestUDPListenPacket(t *testing.T) {
	a1, a2 := udpServe(t, "udp4", echo), udpServe(t, "udp4", func(b []byte) []byte { return append([]byte("2:"), b...) })
	assoc := make(chan *association, 2)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	pc := mustListenPacket(t, d, "udp", "")
	uc := pc
	pc.SetDeadline(time.Now().Add(2 * time.Second))
	if pc.RemoteAddr() != nil {
		t.Errorf("RemoteAddr %v", uc.RemoteAddr())
	}
	if _, err := pc.WriteTo([]byte("a"), net.UDPAddrFromAddrPort(a1)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "a" || from.(*net.UDPAddr).AddrPort() != a1 {
		t.Fatalf("ReadFrom = %q, %v, %v", buf[:n], from, err)
	}
	a2w := wire.AddrFromAddrPort(a2)
	if _, err := uc.WriteToAddr([]byte("b"), a2w); err != nil {
		t.Fatal(err)
	}
	n, fromA, err := uc.ReadFromAddr(buf)
	if err != nil || string(buf[:n]) != "2:b" || fromA != a2w {
		t.Fatalf("ReadFromAddr = %q, %v, %v", buf[:n], fromA, err)
	}
	for _, to := range []net.Addr{a2w, &a2w} {
		if _, err := pc.WriteTo([]byte("c"), to); err != nil {
			t.Fatal(err)
		}
		if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "2:c" {
			t.Fatalf("Read = %q, %v", buf[:n], err)
		}
	}
	// A name goes to the proxy, which answers from the IP.
	if _, err := pc.WriteTo([]byte("d"), mustAddr(fmt.Sprintf("localhost:%d", a1.Port()))); err != nil {
		t.Fatal(err)
	}
	if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "d" || from.String() != a1.String() {
		t.Fatalf("ReadFrom = %q, %v, %v", buf[:n], from, err)
	}
	// A datagram from a name reads as from that wire.Addr.
	named := mustAddr("example.com:53")
	(<-assoc).send(t, append(must(wire.AppendUDPHeader(nil, 0, named)), "named"...))
	if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "named" || from != net.Addr(named) {
		t.Fatalf("ReadFrom = %q, %#v, %v", buf[:n], from, err)
	}

	// ListenUDP: the same, typed.
	u, err := d.ListenUDP(t.Context(), "udp4", "")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.WriteToAddr([]byte("hi"), wire.AddrFromAddrPort(a1)); err != nil {
		t.Fatal(err)
	}
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, from, err := u.ReadFromAddr(buf); err != nil || string(buf[:n]) != "hi" || from != wire.AddrFromAddrPort(a1) {
		t.Errorf("ReadFromAddr = %q, %v, %v", buf[:n], from, err)
	}
	if u, err := d.ListenUDP(t.Context(), "tcp", ""); u != nil || socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("ListenUDP tcp = %v, %v", u, err)
	}
	if pc, err := d.ListenPacket(t.Context(), "tcp", ""); pc != nil || socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("ListenPacket tcp = %#v, %v", pc, err) // a nil interface, not a typed nil
	}
}

// Writes to a bad, missing or other destination fail before any syscall.
func TestUDPWriteErrors(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	open := func(network string) *socks0.UDPConn {
		pc, err := d.ListenPacket(t.Context(), network, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		return pc.(*socks0.UDPConn)
	}
	uc, uc4, uc6 := open("udp"), open("udp4"), open("udp6")
	isOp := func(name string, err error, target error) {
		t.Helper()
		if oe, ok := err.(*net.OpError); !ok || oe.Op != "write" || oe.Net != "udp" || !errors.Is(err, target) {
			t.Errorf("%s: %#v; want *net.OpError{Op: write} matching %v", name, err, target)
		}
		noPanic(t, name+": Error", func() { _ = err.Error() })
	}
	for _, bad := range []net.Addr{&net.TCPAddr{}, nil, (*net.UDPAddr)(nil), &net.UDPAddr{}, (*wire.Addr)(nil), wire.Addr{}} {
		_, err := uc.WriteTo([]byte("x"), bad)
		isOp(fmt.Sprintf("WriteTo(%#v)", bad), err, syscall.EINVAL)
	}
	_, err := uc.WriteToAddr([]byte("x"), wire.Addr{})
	isOp("WriteToAddr(zero)", err, syscall.EINVAL)
	_, err = uc.Write([]byte("x"))
	isOp("Write unconnected", err, eDestAddrReq)

	// udp4 and udp6 restrict IP targets, not names.
	if _, err := uc4.WriteTo([]byte("x"), mustAddr("[2001:db8::1]:53")); !isAddrErr(err) {
		t.Errorf("udp4 to IPv6: %v", err)
	}
	if _, err := uc4.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}); err == nil {
		t.Errorf("udp4 to a *net.UDPAddr IPv6: no error")
	}
	if _, err := uc6.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}); err == nil {
		t.Error("udp6 to IPv4: no error")
	}
	if _, err := uc4.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}); err != nil {
		t.Errorf("udp4 to a 16-byte IPv4 = %v", err)
	}
	a := mustAddr("192.0.2.1:9")
	for _, to := range []net.Addr{mustAddr("example.com:53"), &a} {
		if n, err := uc4.WriteTo([]byte("xy"), to); err != nil || n != 2 {
			t.Errorf("udp4 to %v = %d, %v", to, n, err)
		}
	}

	// A connected conn writes only to its target.
	c := mustDial(t, d, "udp", "192.0.2.1:9")
	cc := c.(*socks0.UDPConn)
	for _, to := range []net.Addr{&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9}, (*wire.Addr)(nil)} {
		_, err := cc.WriteTo([]byte("x"), to)
		if oe, ok := err.(*net.OpError); !ok || oe.Err != net.ErrWriteToConnected {
			t.Errorf("WriteTo(%#v) on a connected conn: %#v", to, err)
		}
		noPanic(t, "connected WriteTo: Error", func() { _ = err.Error() })
	}
	if _, err := cc.WriteToAddr([]byte("x"), a); !errors.Is(err, net.ErrWriteToConnected) {
		t.Errorf("WriteToAddr on a connected conn: %v", err)
	}
}

func isAddrErr(err error) bool {
	_, ok := errors.AsType[*net.AddrError](err)
	return ok
}

// As a Unix UDP socket, a datagram larger than the buffer is truncated without an error.
func TestUDPTruncation(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	c := mustDial(t, d, "udp4", echoAP.String())
	uc := c.(*socks0.UDPConn)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, from, err := uc.ReadFrom(buf); err != nil || string(buf[:n]) != "0123" || from.String() != echoAP.String() {
		t.Fatalf("truncated ReadFrom = %q, %v, %v", buf[:n], from, err)
	}
	a := <-assoc
	hdr, _ := wire.AppendUDPHeader(nil, 0, mustAddr(echoAP.String()))
	a.send(t, append(slices.Clip(hdr), strings.Repeat("A", 3000)...))
	a.send(t, append(slices.Clip(hdr), "next"...))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "AAAA" {
		t.Fatalf("Read = %q %v", buf[:n], err)
	}
	if s := readN(t, c, 4); s != "next" {
		t.Fatalf("2nd Read = %q", s)
	}
	a.send(t, append(slices.Clip(hdr), "zzz"...))
	if n, err := c.Read(nil); err != nil || n != 0 {
		t.Fatalf("Read(nil) = %d %v", n, err)
	}
}

// Loopback takes exactly 65507 (IPv4) / 65527 (IPv6) bytes of UDP payload on
// Linux: socks0's largest must pass there, one more fail before any syscall.
func TestUDPMessageSize(t *testing.T) {
	name255 := strings.Repeat("a", 251) + ".com"
	for _, relay := range []string{"udp4", "udp6"} {
		for _, target := range []string{"192.0.2.1:9", "[2001:db8::1]:9", "x:9", name255 + ":9"} {
			for _, path := range []string{"dial", "listen", "relaylisten"} {
				t.Run(relay+"/"+target[:min(len(target), 16)]+"/"+path, func(t *testing.T) {
					if relay == "udp6" && !hasIPv6() {
						t.Skip("no IPv6")
					}
					to := mustAddr(target)
					ipHdr := map[string]int{"udp4": 20, "udp6": 0}[relay]
					max := 65535 - 8 - ipHdr - wire.UDPHeaderLen(to)
					raw := make(chan []byte, 8)
					d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{network: relay, raw: raw}.serve)}
					if path == "relaylisten" {
						d.RelayListen = new(net.ListenConfig).ListenPacket
					}
					var write func([]byte) (int, error)
					if path == "dial" {
						c := mustDial(t, d, "udp", target)
						write = c.Write
					} else {
						pc := mustListenPacket(t, d, "udp", "")
						write = func(b []byte) (int, error) { return pc.WriteToAddr(b, to) }
					}
					_, err := write(make([]byte, max+1))
					if oe, ok := err.(*net.OpError); !ok || oe.Op != "write" || !errors.Is(err, eMsgSize) {
						t.Errorf("payload max+1=%d: %#v; want EMSGSIZE", max+1, err)
					}
					n, err := write(make([]byte, max))
					switch {
					case runtime.GOOS != "linux": // the kernel may refuse it
						if err != nil && !errors.Is(err, eMsgSize) && !errors.Is(err, eNoBufs) {
							t.Errorf("payload %d: %v", max, err)
						}
					case err != nil || n != max:
						t.Fatalf("payload max=%d: %d, %v", max, n, err)
					default:
						select {
						case b := <-raw:
							if len(b) != max+wire.UDPHeaderLen(to) {
								t.Errorf("proxy got %d bytes, want %d", len(b), max+wire.UDPHeaderLen(to))
							}
						case <-time.After(2 * time.Second):
							t.Error("proxy got nothing")
						}
					}
					if _, err := write(make([]byte, 1200)); err != nil {
						t.Errorf("payload 1200: %v", err)
					}
				})
			}
		}
	}
}

func TestUDPDropped(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	assoc := make(chan *association, 1)
	type drop struct {
		from wire.Addr
		err  error
	}
	var (
		mu    sync.Mutex
		drops []drop
	)
	d := &socks0.Dialer{
		ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve),
		Config: &socks0.Config{Trace: &socks0.ClientTrace{DroppedDatagram: func(from wire.Addr, err error) {
			mu.Lock()
			drops = append(drops, drop{from, err})
			mu.Unlock()
		}}},
	}
	c := mustDial(t, d, "udp", echoAP.String())
	a := <-assoc
	if s := roundTrip(t, c, "first"); s != "first" { // the server learns our address
		t.Fatal(s)
	}
	other, target := mustAddr("192.0.2.7:53"), mustAddr(echoAP.String())
	hdr := func(frag uint8, a wire.Addr) []byte { return must(wire.AppendUDPHeader(nil, frag, a)) }
	junk := [][]byte{
		append(hdr(1, target), "fragment"...),
		append(hdr(0, other), "wrong source"...),
		{0, 0, 0, 9, 1, 2, 3},       // bad ATYP
		{0, 0, 0, 1, 127},           // truncated
		{0, 0, 0, 1, 1, 2},          // truncated
		{0, 0, 0, 3, 0, 0, 0, 1, 2}, // empty name
	}
	for _, b := range append(junk, append(hdr(0, target), "good"...)) {
		a.send(t, b)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "good" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	mu.Lock()
	got := slices.Clone(drops)
	mu.Unlock()
	if len(got) != len(junk) {
		t.Fatalf("drops %v", got)
	}
	if got[0].from != target || got[0].err != socks0.ErrFragment || got[1].from != other || got[1].err != socks0.ErrWrongSource {
		t.Errorf("drops %v", got[:2])
	}
	for _, dr := range got[2:] {
		if pe, ok := errors.AsType[*socks0.ProtocolError](dr.err); !ok || pe.Stage != wire.StageUDPHeader || dr.from.IsValid() {
			t.Errorf("drop: %v, %#v", dr.from, dr.err)
		}
	}
	// Only junk: the deadline still applies across dropped datagrams.
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 10 {
			a.send(t, junk[1])
			time.Sleep(10 * time.Millisecond)
		}
	})
	start := time.Now()
	_, err := c.Read(buf)
	wg.Wait()
	if !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || time.Since(start) > time.Second {
		t.Errorf("Read = %v after %v", err, time.Since(start))
	}
	if oe, ok := err.(*net.OpError); !ok || !oe.Timeout() || oe.Op != "read" {
		t.Errorf("err %#v", err)
	}
}

// The UDP ASSOCIATE's DST, from AssociateAddr or ListenPacket's address; a port needs RelayDial.
func TestUDPAssociateDST(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	for _, tt := range []struct {
		name            string
		network, target string // DialContext's; "" for udp and the echo server
		assoc           string // AssociateAddr
		listen          *string
		relayDial       bool
		want            string // DST; "" for a config error
	}{
		{name: "default", want: "0.0.0.0:0"},
		{name: "AssociateAddr", assoc: "192.0.2.9:0", want: "192.0.2.9:0"},
		{name: "AssociateAddr port", assoc: "192.0.2.9:4000"},
		{name: "AssociateAddr port RelayDial", assoc: "192.0.2.9:4000", relayDial: true, want: "192.0.2.9:4000"},
		{name: "AssociateAddr bad", assoc: "nope"},
		{name: "target bad", target: "nonsense"},
		{name: "target port", target: "host:99999"},
		{name: "udp6 IPv4 target", network: "udp6", target: "192.0.2.1:53"},
		{name: "listen empty", listen: new(""), want: "0.0.0.0:0"},
		{name: "listen :0", listen: new(":0"), want: "0.0.0.0:0"},
		{name: "listen 0.0.0.0:0", listen: new("0.0.0.0:0"), want: "0.0.0.0:0"},
		{name: "listen [::]:0", listen: new("[::]:0"), want: "0.0.0.0:0"},
		{name: "listen IP", listen: new("192.0.2.1:0"), want: "192.0.2.1:0"},
		{name: "listen IPv4-mapped", listen: new("[::ffff:192.0.2.1]:0"), want: "192.0.2.1:0"},
		{name: "listen overrides", assoc: "192.0.2.9:0", listen: new("198.51.100.1:0"), want: "198.51.100.1:0"},
		{name: "listen port", listen: new("198.51.100.1:53")},
		{name: "listen :53", listen: new(":53")},
		{name: "listen port RelayDial", listen: new("198.51.100.1:53"), relayDial: true, want: "198.51.100.1:53"},
		{name: "listen bad", listen: new("198.51.100.1")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan wire.Addr, 1)
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{got: got}.serve), AssociateAddr: tt.assoc}
			if tt.relayDial {
				d.RelayDial = new(net.Dialer).DialContext
			}
			var c io.Closer
			var err error
			if tt.listen != nil {
				c, err = d.ListenPacket(t.Context(), "udp", *tt.listen)
			} else {
				c, err = d.DialContext(t.Context(), cmp.Or(tt.network, "udp"), cmp.Or(tt.target, echoAP.String()))
			}
			if tt.want == "" {
				if socks0.KindOf(err) != socks0.KindConfig || handshakeErrOf(t, err).Stage != socks0.StageConfig {
					t.Fatalf("err = %v; want a config error", err)
				}
				if tt.listen == nil && strings.Contains(err.Error(), "0.0.0.0:0") {
					t.Errorf("error names DST 0.0.0.0:0 as the target: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			if dst := <-got; dst != mustAddr(tt.want) {
				t.Errorf("DST %v, want %v", dst, tt.want)
			}
		})
	}
}

// The relay is dialed at BND, its unspecified address substituted by the proxy's.
func TestUDPRelayAddr(t *testing.T) {
	v6 := hasIPv6()
	private := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("10.255.255.1:%d", ap.Port())) }
	name := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("localhost:%d", ap.Port())) }
	for _, tt := range []struct {
		name        string
		relay       string // relay network
		listen      string // proxy listener: "tcp4" (127.0.0.1) or "tcp6"
		host        string // ProxyAddr host
		bnd         func(netip.AddrPort) wire.Addr
		chain       bool // ProxyDial dials the listener's family
		relayDial   bool
		relayListen bool
		proxyHost   bool
		wantNet     string
		wantHost    string // relay dialed at wantHost:BND.PORT
		roundTrip   bool
		needsIPv6   bool
		needsLocal  bool // localhost resolves to 127.0.0.1 and ::1
	}{
		{name: "BND as is", wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
		{name: "0.0.0.0 IP ProxyAddr", bnd: unspec4, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
		{name: ":: IP ProxyAddr", bnd: unspec6, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
		{name: "0.0.0.0 named ProxyAddr", host: "localhost", bnd: unspec4, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
		{name: "0.0.0.0 named chained", host: "localhost", bnd: unspec4, chain: true, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
		{name: "0.0.0.0 named chained RelayDial", host: "localhost", bnd: unspec4, chain: true, relayDial: true, wantNet: "udp", wantHost: "localhost"},
		{name: "private BND", bnd: private, wantNet: "udp4", wantHost: "10.255.255.1"},
		{name: "private BND RelayUseProxyHost", bnd: private, proxyHost: true, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
		{name: "name BND", bnd: name, wantNet: "udp", wantHost: "localhost"},
		{name: "IPv6", relay: "udp6", listen: "tcp6", host: "::1", wantNet: "udp6", wantHost: "::1", roundTrip: true, needsIPv6: true},
		{name: ":: IPv6", relay: "udp6", listen: "tcp6", host: "::1", bnd: unspec6, wantNet: "udp6", wantHost: "::1", roundTrip: true, needsIPv6: true},
		// A named proxy: the peer's address family decides.
		{name: "0.0.0.0 over IPv6 control", listen: "tcp6", host: "localhost", bnd: unspec4, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true, needsLocal: true},
		{name: ":: over IPv6 control", relay: "udp6", listen: "tcp6", host: "localhost", bnd: unspec6, wantNet: "udp6", wantHost: "::1", roundTrip: true, needsLocal: true},
		{name: ":: over IPv4 control", listen: "tcp4", host: "localhost", bnd: unspec6, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true, needsLocal: true},
		{name: "chained :: over IPv6 control", relay: "udp6", listen: "tcp6", host: "localhost", bnd: unspec6, chain: true, wantNet: "udp6", wantHost: "::1", roundTrip: true, needsLocal: true},
		{name: "chained 0.0.0.0 over IPv6 control", listen: "tcp6", host: "localhost", bnd: unspec4, chain: true, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true, needsLocal: true},
		{name: "chained :: over IPv4 control", listen: "tcp4", host: "localhost", bnd: unspec6, chain: true, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true, needsLocal: true},
		{name: "RelayListen chained 0.0.0.0 over IPv6 control", listen: "tcp6", host: "localhost", bnd: unspec4, chain: true, relayListen: true, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true, needsLocal: true},
		{name: "RelayListen chained :: over IPv6 control", relay: "udp6", listen: "tcp6", host: "localhost", bnd: unspec6, chain: true, relayListen: true, wantNet: "udp6", wantHost: "::1", roundTrip: true, needsLocal: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.needsIPv6 || tt.needsLocal) && !v6 {
				t.Skip("no IPv6 loopback")
			}
			if tt.needsLocal {
				ips, _ := net.DefaultResolver.LookupNetIP(t.Context(), "ip", "localhost")
				if !slices.Contains(ips, netip.MustParseAddr("::1")) || !slices.Contains(ips, netip.MustParseAddr("127.0.0.1")) {
					t.Skip("localhost is not 127.0.0.1 and ::1")
				}
			}
			listenNet := cmp.Or(tt.listen, "tcp4")
			echoAP := udpServe(t, cmp.Or(tt.relay, "udp4"), echo)
			_, port, _ := net.SplitHostPort(listenOn(t, listenNet, udpProxy{network: tt.relay, bnd: tt.bnd}.serve))
			var dialed []string
			d := &socks0.Dialer{
				ProxyAddr:         net.JoinHostPort(cmp.Or(tt.host, "127.0.0.1"), port),
				RelayUseProxyHost: tt.proxyHost,
				Config: &socks0.Config{Trace: &socks0.ClientTrace{
					RelayDialStart: func(network, addr string) { dialed = append(dialed, network, addr) },
				}},
			}
			if tt.chain {
				d.ProxyDial = func(ctx context.Context, _, addr string) (net.Conn, error) {
					return new(net.Dialer).DialContext(ctx, listenNet, addr)
				}
			}
			if tt.relayDial {
				d.RelayDial = new(net.Dialer).DialContext
			}
			if tt.relayListen {
				d.RelayListen = new(net.ListenConfig).ListenPacket
			}
			c := mustDial(t, d, "udp", echoAP.String())
			uc := c.(*socks0.UDPConn)
			if want := []string{tt.wantNet, net.JoinHostPort(tt.wantHost, fmt.Sprint(uc.BoundAddr().Port()))}; !slices.Equal(dialed, want) {
				t.Errorf("relay dialed %q, want %q", dialed, want)
			}
			if tt.roundTrip {
				if s := roundTrip(t, c, "hi"); s != "hi" {
					t.Errorf("echo %q", s)
				}
			}
		})
	}
}

func TestUDPBNDPortZero(t *testing.T) {
	zero := func(netip.AddrPort) wire.Addr { return mustAddr("127.0.0.1:0") }
	for _, mode := range modes {
		d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{bnd: zero}.serve), Config: &socks0.Config{Mode: mode}}
		_, err := d.ListenPacket(t.Context(), "udp", "")
		he := handshakeErrOf(t, err)
		pe, ok := errors.AsType[*socks0.ProtocolError](err)
		if !ok || pe.Field != wire.FieldPORT || he.Stage != wire.StageReply || socks0.KindOf(err) != socks0.KindProtocol || err.(*net.OpError).Op != "socks udp associate" {
			t.Errorf("%v: err = %v", mode, err)
		}
	}
}

// With RelayListen, datagrams from another port of the relay's host are accepted, others dropped.
func TestUDPRelayListen(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	// A NAT-like proxy answers from another port: only RelayListen sees it.
	for _, unconnected := range []bool{false, true} {
		t.Run(fmt.Sprint("RelayListen=", unconnected), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{nat: true}.serve)}
			if unconnected {
				d.RelayListen = new(net.ListenConfig).ListenPacket
			}
			c := mustDial(t, d, "udp", echoAP.String())
			uc := c.(*socks0.UDPConn)
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			c.Write([]byte("nat"))
			buf := make([]byte, 16)
			n, err := c.Read(buf)
			if unconnected {
				if err != nil || string(buf[:n]) != "nat" || uc.RelayAddr().String() != uc.BoundAddr().String() {
					t.Fatalf("Read = %q, %v; RelayAddr %v", buf[:n], err, uc.RelayAddr())
				}
			} else if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("connected relay: Read = %q, %v; want a timeout", buf[:n], err)
			}
		})
	}
	t.Run("another host", func(t *testing.T) {
		assoc := make(chan *association, 1)
		var (
			mu    sync.Mutex
			drops []wire.Addr
		)
		d := &socks0.Dialer{
			ProxyAddr:   listen(t, udpProxy{assoc: assoc, nat: true}.serve),
			RelayListen: new(net.ListenConfig).ListenPacket,
			Config: &socks0.Config{Trace: &socks0.ClientTrace{DroppedDatagram: func(from wire.Addr, err error) {
				mu.Lock()
				drops = append(drops, from)
				mu.Unlock()
			}}},
		}
		pc := mustListenPacket(t, d, "udp", "")
		a := <-assoc
		pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:9")))
		<-a.first
		s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
		if err != nil {
			t.Skip("no 127.0.0.2")
		}
		defer s.Close()
		hdr, _ := wire.AppendUDPHeader(nil, 0, mustAddr("192.0.2.1:9"))
		s.WriteToUDPAddrPort(append(slices.Clip(hdr), "spoof"...), a.clientAddr())
		a.send(t, append(slices.Clip(hdr), "ok"...))
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 100)
		if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "ok" || from.String() != "192.0.2.1:9" {
			t.Fatalf("ReadFrom = %q %v %v", buf[:n], from, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if want := wire.AddrFromAddrPort(s.LocalAddr().(*net.UDPAddr).AddrPort()); len(drops) != 1 || drops[0] != want {
			t.Errorf("drops = %v, want [%v]", drops, want)
		}
	})
	t.Run("and RelayDial", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1", RelayListen: new(net.ListenConfig).ListenPacket, RelayDial: new(net.Dialer).DialContext}
		if _, err := d.ListenPacket(t.Context(), "udp", ""); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("err = %v", err)
		}
	})
}

// The proxy ending the control conn ends the association: ErrAssociationClosed, wrapping its cause.
func TestUDPAssociationEndedByProxy(t *testing.T) {
	for _, how := range []string{"close", "reset", "half-close"} {
		t.Run(how, func(t *testing.T) {
			base := runtime.NumGoroutine()
			assoc := make(chan *association, 1)
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
			c := mustDial(t, d, "udp", "192.0.2.1:9")
			uc := c.(*socks0.UDPConn)
			a := <-assoc
			read := readErr(c)
			time.Sleep(20 * time.Millisecond)
			switch how {
			case "close":
				a.control.Close()
			case "reset":
				a.control.(*net.TCPConn).SetLinger(0)
				a.control.Close()
			case "half-close":
				a.control.(*net.TCPConn).CloseWrite()
			}
			var rerr error
			select {
			case rerr = <-read:
			case <-time.After(2 * time.Second):
				t.Fatal("Read still blocked")
			}
			select {
			case <-uc.Done():
			case <-time.After(time.Second):
				t.Fatal("Done not closed")
			}
			_, werr := c.Write([]byte("x"))
			for _, err := range []error{rerr, werr, uc.Err()} {
				if !errors.Is(err, socks0.ErrAssociationClosed) || socks0.KindOf(err) != socks0.KindAssociation || errors.Is(err, net.ErrClosed) {
					t.Errorf("err = %v; want ErrAssociationClosed", err)
				}
				if how != "reset" && !errors.Is(err, io.EOF) || how == "reset" && !errors.Is(err, eConnReset) && !errors.Is(err, io.EOF) {
					t.Errorf("err = %v; want the control conn's error wrapped", err)
				}
			}
			if oe, ok := rerr.(*net.OpError); !ok || oe.Op != "read" || oe.Net != "udp" {
				t.Errorf("read error %#v", rerr)
			}
			// A local Close after the proxy's end succeeds, once.
			if err := c.Close(); err != nil {
				t.Errorf("Close after the proxy ended: %v", err)
			}
			if err := c.Close(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("2nd Close = %v", err)
			}
			_, rerr = c.Read(make([]byte, 10))
			_, werr = c.Write([]byte("x"))
			if !errors.Is(rerr, net.ErrClosed) || !errors.Is(werr, net.ErrClosed) {
				t.Errorf("after Close: Read %v, Write %v", rerr, werr)
			}
			if how == "half-close" {
				a.control.Close()
			}
			waitGoroutines(t, base+2) // listener goroutines of the fake proxy may linger
		})
	}
}

// A user Close ends Reads and Writes with net.ErrClosed, never ErrAssociationClosed.
func TestUDPClose(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	userClosed := func(err error) bool {
		return errors.Is(err, net.ErrClosed) && !errors.Is(err, socks0.ErrAssociationClosed) && socks0.KindOf(err) == socks0.KindClosed
	}
	base := runtime.NumGoroutine()
	c := mustDial(t, d, "udp", echoAP.String())
	uc := c.(*socks0.UDPConn)
	a := <-assoc
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			buf := make([]byte, 16)
			for {
				if _, err := c.Read(buf); err != nil {
					if !userClosed(err) {
						t.Errorf("Read: %v", err)
					}
					return
				}
			}
		})
		wg.Go(func() {
			for {
				if _, err := c.Write([]byte("x")); err != nil {
					if !userClosed(err) {
						t.Errorf("Write: %v", err)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	time.Sleep(30 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := c.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("second Close: %v", err)
	}
	select {
	case <-uc.Done():
	default:
		t.Error("Done not closed")
	}
	if !userClosed(uc.Err()) {
		t.Errorf("Err() = %v", uc.Err())
	}
	<-a.ended
	waitGoroutines(t, base)

	for i := range 50 { // Close racing a Read's start
		c := mustDial(t, d, "udp", "192.0.2.1:9")
		<-assoc
		rerr := readErr(c)
		if i%2 == 0 {
			time.Sleep(time.Millisecond)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		_, werr := c.Write([]byte("x"))
		if err := <-rerr; !userClosed(err) || !userClosed(werr) || !userClosed(c.(*socks0.UDPConn).Err()) {
			t.Fatalf("after user Close: Read %v, Write %v, Err %v", err, werr, c.(*socks0.UDPConn).Err())
		}
		select {
		case <-c.(*socks0.UDPConn).Done():
		default:
			t.Fatal("Done open after Close returned")
		}
	}
}

// The relay's ECONNREFUSED may beat the control EOF: the association's end still surfaces as such.
func TestUDPCloseRacesProxyEnd(t *testing.T) {
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	t.Run("proxy end", func(t *testing.T) {
		counts := map[socks0.Kind]int{}
		for range 100 {
			c := mustDial(t, d, "udp", "192.0.2.1:9")
			(<-assoc).control.Close()
			var kind socks0.Kind
			for range 1000 {
				if _, err := c.Write([]byte("x")); err != nil {
					kind = socks0.KindOf(err)
					break
				}
				c.SetReadDeadline(time.Now().Add(time.Millisecond))
				if _, err := c.Read(make([]byte, 4)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
					kind = socks0.KindOf(err)
					break
				}
			}
			counts[kind]++
			c.Close()
		}
		if counts[socks0.KindRefused] > 0 {
			t.Errorf("%d/100 associations ended by the proxy surfaced as KindRefused, not KindAssociation: %v", counts[socks0.KindRefused], counts)
		}
	})
	t.Run("and user Close", func(t *testing.T) {
		base := runtime.NumGoroutine()
		var refused atomic.Int32
		for range 100 {
			c := mustDial(t, d, "udp", "192.0.2.1:9")
			a := <-assoc
			check := func(what string, err error) {
				switch {
				case err == nil, errors.Is(err, net.ErrClosed), errors.Is(err, socks0.ErrAssociationClosed):
				case errors.Is(err, eConnRefused):
					refused.Add(1)
				default:
					t.Errorf("%s: %v", what, err)
				}
			}
			var wg sync.WaitGroup
			wg.Go(func() { _, err := c.Read(make([]byte, 10)); check("read", err) })
			wg.Go(func() {
				for range 20 {
					_, err := c.Write([]byte("x"))
					if check("write", err); err != nil {
						return
					}
				}
			})
			wg.Go(func() { a.control.Close() })
			wg.Go(func() { c.Close() })
			wg.Go(func() { c.SetDeadline(time.Now().Add(time.Second)) })
			wg.Wait()
			<-c.(*socks0.UDPConn).Done()
		}
		if n := refused.Load(); n > 0 {
			t.Errorf("ECONNREFUSED instead of ErrAssociationClosed: %d times", n)
		}
		waitGoroutines(t, base+2)
	})
}

func TestUDPConcurrentUse(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	base := runtime.NumGoroutine()
	uc := mustListenPacket(t, d, "udp", "")
	var (
		stop atomic.Bool
		got  atomic.Int64
		wg   sync.WaitGroup
	)
	bad := func(err error) bool {
		return err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, socks0.ErrAssociationClosed)
	}
	for i := range 8 {
		wg.Go(func() {
			buf := make([]byte, 64+i)
			for !stop.Load() {
				var err error
				if i%2 == 0 {
					_, _, err = uc.ReadFromAddr(buf)
				} else {
					_, _, err = uc.ReadFrom(buf)
				}
				if bad(err) {
					t.Errorf("read: %v", err)
				}
				if err == nil {
					got.Add(1)
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
			}
		})
		wg.Go(func() {
			to, msg := wire.AddrFromAddrPort(echoAP), []byte(fmt.Sprint("msg", i))
			for !stop.Load() {
				var err error
				if i%2 == 0 {
					_, err = uc.WriteToAddr(msg, to)
				} else {
					_, err = uc.WriteTo(msg, net.UDPAddrFromAddrPort(echoAP))
				}
				if bad(err) {
					t.Errorf("write: %v", err)
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	wg.Go(func() {
		for !stop.Load() {
			uc.SetDeadline(time.Now().Add(5 * time.Millisecond))
			uc.SetReadDeadline(time.Time{})
			uc.SetWriteDeadline(time.Time{})
			_ = uc.Err()
			_ = uc.LocalAddr()
			time.Sleep(time.Millisecond)
		}
	})
	time.Sleep(300 * time.Millisecond)
	var cwg sync.WaitGroup
	for range 4 {
		cwg.Go(func() { uc.Close() })
	}
	cwg.Wait()
	stop.Store(true)
	wg.Wait()
	if got.Load() == 0 {
		t.Error("no datagram echoed")
	}
	waitGoroutines(t, base+2)
}

// Leaked UDPConns are closed by the GC; closed ones leave nothing behind.
func TestUDPCleanup(t *testing.T) {
	const n = 10
	assoc := make(chan *association, n)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	runtime.GC()
	base := runtime.NumGoroutine()
	func() {
		for i := range n {
			var c net.Conn
			var err error
			if i%2 == 0 {
				c, err = d.DialContext(t.Context(), "udp", "192.0.2.1:9")
			} else {
				var pc net.PacketConn
				if pc, err = d.ListenPacket(t.Context(), "udp", ""); pc != nil {
					c = pc.(net.Conn)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(time.Millisecond))
			c.Read(make([]byte, 10))
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for range n {
		a := <-assoc
		for ended := false; !ended; {
			runtime.GC()
			select {
			case <-a.ended:
				ended = true
			case <-time.After(10 * time.Millisecond):
				if time.Now().After(deadline) {
					t.Fatal("leaked UDPConn not cleaned up")
				}
			}
		}
	}
	waitGoroutines(t, base)

	for range 20 {
		c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
		if err != nil {
			t.Fatal(err)
		}
		<-assoc
		c.Close()
	}
	for range 5 {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	}
	waitGoroutines(t, base+2)
}

// A control conn whose Read ignores Close and deadlines (any net.Conn may) bounds Close
// to about a second and does not block the runtime's cleanups of leaked UDPConns.
func TestUDPStuckControl(t *testing.T) {
	stuck := func(t *testing.T) (*memConn, *net.UDPConn) {
		mc := newMem()
		mc.readIgnoresClose, mc.ignoreDeadlines = true, true
		t.Cleanup(func() { close(mc.releaseRead) })
		rc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		if err != nil {
			t.Fatal(err)
		}
		return mc, rc
	}
	t.Run("Close", func(t *testing.T) {
		mc, rc := stuck(t)
		u := socks0.NewUDPConn(mc, rc, wire.Addr{})
		start := time.Now()
		if err := u.Close(); err != nil {
			t.Fatal(err)
		}
		if el := time.Since(start); el < 900*time.Millisecond || el > 5*time.Second {
			t.Errorf("Close took %v, want about 1s", el)
		}
		if mc.closes.Load() == 0 || !errors.Is(u.Err(), net.ErrClosed) {
			t.Errorf("control closed %d times, Err = %v", mc.closes.Load(), u.Err())
		}
	})
	t.Run("cleanup", func(t *testing.T) {
		mc, rc := stuck(t)
		func() { _ = socks0.NewUDPConn(mc, rc, wire.Addr{}) }() // leaked
		for range 5 {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
		if mc.closes.Load() == 0 {
			t.Error("the leaked UDPConn's control conn was not closed by the GC cleanup")
		}
		ran := make(chan struct{})
		func() {
			x := new([16]byte)
			runtime.AddCleanup(x, func(ch chan struct{}) { close(ch) }, ran)
		}()
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			runtime.GC()
			select {
			case <-ran:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		t.Error("an unrelated cleanup did not run within 2s: the UDPConn cleanup blocks a runtime cleanup goroutine")
	})
}

func TestUDPErrors(t *testing.T) {
	errDial := errors.New("relay dial failed")
	for _, tt := range []struct {
		name  string
		p     udpProxy
		d     socks0.Dialer
		stage string
		kind  socks0.Kind
		is    error
	}{
		{name: "not supported", p: udpProxy{rep: wire.ReplyCommandNotSupported}, stage: wire.StageReply, kind: socks0.KindReply, is: errors.ErrUnsupported},
		{name: "relay dial", d: socks0.Dialer{RelayDial: func(context.Context, string, string) (net.Conn, error) { return nil, errDial }}, stage: socks0.StageRelayDial, kind: socks0.KindOther, is: errDial},
		{name: "relay dial nil", d: socks0.Dialer{RelayDial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}, stage: socks0.StageRelayDial, kind: socks0.KindOther},
		{name: "relay listen", d: socks0.Dialer{RelayListen: func(context.Context, string, string) (net.PacketConn, error) { return nil, errDial }}, stage: socks0.StageRelayDial, kind: socks0.KindOther, is: errDial},
		{name: "unknown network", stage: socks0.StageConfig, kind: socks0.KindConfig},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var ev events
			d := tt.d
			d.ProxyAddr = listen(t, tt.p.serve)
			d.Config = &socks0.Config{Trace: ev.trace("t")}
			network := "udp"
			if tt.name == "unknown network" {
				network = "ip"
			}
			pc, err := d.ListenPacket(t.Context(), network, "")
			if pc != nil {
				t.Fatalf("pc = %v", pc)
			}
			he := handshakeErrOf(t, err)
			if he.Stage != tt.stage || socks0.KindOf(err) != tt.kind || tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v: stage %q, kind %q", err, he.Stage, socks0.KindOf(err))
			}
			if got := only(ev.get(), "t"); tt.stage == socks0.StageRelayDial && !slices.Equal(got[max(len(got)-3, 0):], []string{"RelayDialStart udp4", "RelayDialDone err", "HandshakeDone err"}) {
				t.Errorf("trace %q", got)
			}
		})
	}
	// The OpError of a refused association.
	rep7 := listen(t, udpProxy{rep: wire.ReplyCommandNotSupported}.serve)
	_, err := (&socks0.Dialer{ProxyAddr: rep7}).DialContext(t.Context(), "udp4", "192.0.2.1:53")
	oe, ok := err.(*net.OpError)
	if !ok || oe.Op != "socks udp associate" || oe.Net != "udp4" || oe.Source == nil || oe.Source.String() != rep7 ||
		oe.Addr == nil || oe.Addr.String() != "192.0.2.1:53" || handshakeErrOf(t, err).Stage != wire.StageReply {
		t.Errorf("err = %#v", err)
	}
	// BND 0.0.0.0 to substitute, the proxy's name not resolving: a DNS error; the control conn closed.
	assoc := make(chan *association, 1)
	addr := listen(t, udpProxy{bnd: unspec4, assoc: assoc}.serve)
	base := runtime.NumGoroutine()
	d := &socks0.Dialer{ProxyAddr: "no-such-host.invalid:1080", ProxyDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, addr)
	}}
	_, err = d.ListenPacket(t.Context(), "udp", "")
	if he := handshakeErrOf(t, err); he.Stage != socks0.StageRelayDial || socks0.KindOf(err) != socks0.KindDNS {
		t.Errorf("err = %v; stage %q kind %q", err, he.Stage, socks0.KindOf(err))
	}
	select {
	case a := <-assoc:
		select {
		case <-a.ended:
		case <-time.After(time.Second):
			t.Error("control conn not closed")
		}
	case <-time.After(time.Second):
	}
	waitGoroutines(t, base+1)
}

func TestUDPCancel(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listen(t, func(c net.Conn) { io.Copy(io.Discard, c) })}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, err := d.DialContext(ctx, "udp", "192.0.2.1:53"); !errors.Is(err, context.Canceled) || handshakeErrOf(t, err).Stage != wire.StageMethodSelection {
		t.Errorf("err = %v", err)
	}
	// Canceled after the setup: the association lives on.
	echoAP := udpServe(t, "udp4", echo)
	d = &socks0.Dialer{ProxyAddr: listenProxy(t)}
	ctx, cancel = context.WithCancel(t.Context())
	c, err := d.DialContext(ctx, "udp", echoAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	time.Sleep(20 * time.Millisecond)
	if s := roundTrip(t, c, "after cancel"); s != "after cancel" {
		t.Errorf("echo %q", s)
	}
	select {
	case <-c.(*socks0.UDPConn).Done():
		t.Error("association ended by ctx cancel")
	default:
	}
}

func TestUDPDeadlines(t *testing.T) {
	to := mustAddr("192.0.2.1:9")
	for _, relayListen := range []bool{false, true} {
		for _, connected := range []bool{false, true} {
			name := fmt.Sprintf("RelayListen=%v connected=%v", relayListen, connected)
			d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
			if relayListen {
				d.RelayListen = new(net.ListenConfig).ListenPacket
			}
			var uc *socks0.UDPConn
			if connected {
				c := mustDial(t, d, "udp", to.String())
				uc = c.(*socks0.UDPConn)
			} else {
				uc = mustListenPacket(t, d, "udp", "")
			}
			write := func() error { _, err := uc.Write([]byte("x")); return err }
			if !connected {
				write = func() error { _, err := uc.WriteTo([]byte("x"), to); return err }
			}
			uc.SetWriteDeadline(time.Unix(1, 0))
			if err := write(); !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || !err.(net.Error).Timeout() {
				t.Errorf("%s: Write past deadline = %#v", name, err)
			}
			uc.SetWriteDeadline(time.Time{})
			uc.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			if _, _, err := uc.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout {
				t.Errorf("%s: ReadFrom = %v", name, err)
			}
			uc.SetDeadline(time.Time{})
			if err := write(); err != nil {
				t.Errorf("%s: Write after clearing = %v", name, err)
			}
			uc.Close()
		}
	}
}

func TestUDPResolver(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.53")
	for _, tc := range []bool{false, true} {
		t.Run(fmt.Sprint("truncated=", tc), func(t *testing.T) {
			dnsUDP := udpServe(t, "udp4", dnsAnswer(want, tc))
			tcpAddr := dnsTCP(t, dnsAnswer(want, false))
			var (
				mu   sync.Mutex
				nets []string
			)
			d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				mu.Lock()
				nets = append(nets, network)
				mu.Unlock()
				if network == "tcp" {
					return d.DialContext(ctx, network, tcpAddr)
				}
				return d.DialContext(ctx, network, dnsUDP.String())
			}}
			ips, err := r.LookupNetIP(t.Context(), "ip4", "example.test.")
			if err != nil || len(ips) != 1 || ips[0] != want {
				t.Fatalf("LookupNetIP = %v, %v", ips, err)
			}
			if mu.Lock(); nets[0] != "udp" || tc != slices.Contains(nets, "tcp") {
				t.Errorf("dialed %v", nets)
			}
			mu.Unlock()
		})
	}
}

// beevik/ntp takes a Dialer func(localAddress, remoteAddress string) (net.Conn, error).
func TestUDPNTPDialer(t *testing.T) {
	ntpd := udpServe(t, "udp4", func(q []byte) []byte {
		if len(q) != 48 || q[0]&7 != 3 { // client mode
			return nil
		}
		r := make([]byte, 48)
		r[0] = 0x24 // version 4, server mode
		copy(r[24:32], q[40:48])
		return r
	})
	d := &socks0.Dialer{ProxyAddr: listenProxy(t), Config: &socks0.Config{Mode: socks0.ModeEarly}}
	dialer := func(_, remote string) (net.Conn, error) { return d.DialContext(t.Context(), "udp", remote) }
	c, err := dialer("", ntpd.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := make([]byte, 48)
	q[0] = 0x23
	copy(q[40:], "transmit")
	if r := roundTrip(t, c, string(q)); len(r) != 48 || r[24:32] != "transmit" {
		t.Errorf("answer % x", r)
	}
}

// SyscallConn reaches the relay socket, also through a UDPConn relay.
func TestUDPSyscallConn(t *testing.T) {
	rc, err := mustListenPacket(t, &socks0.Dialer{ProxyAddr: listenProxy(t)}, "udp", "").SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if fdOK := false; rc.Control(func(fd uintptr) { fdOK = fd > 0 }) != nil || !fdOK {
		t.Error("Control")
	}
	echoAP := udpServe(t, "udp4", echo)
	outer := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	inner := &socks0.Dialer{ProxyAddr: listenProxy(t), RelayDial: outer.DialContext}
	c := mustDial(t, inner, "udp", echoAP.String())
	if s := roundTrip(t, c, "nested"); s != "nested" {
		t.Errorf("echo %q", s)
	}
	if _, err := c.(*socks0.UDPConn).SyscallConn(); err != nil {
		t.Errorf("SyscallConn over a UDPConn relay: %v", err)
	}
}

// A round trip allocates nothing, connected or not, with either relay socket.
func TestUDPAllocs(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	to := wire.AddrFromAddrPort(echoAP)
	for _, relayListen := range []bool{false, true} {
		d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
		if relayListen {
			d.RelayListen = new(net.ListenConfig).ListenPacket
		}
		c := mustDial(t, d, "udp", echoAP.String())
		uc := mustListenPacket(t, d, "udp", "")
		payload, buf := make([]byte, 256), make([]byte, 512)
		roundTrip(t, c, "warm up")
		for name, f := range map[string]func() error{
			"Write+Read": func() error {
				if _, err := c.Write(payload); err != nil {
					return err
				}
				_, err := c.Read(buf)
				return err
			},
			"WriteToAddr+ReadFromAddr": func() error {
				if _, err := uc.WriteToAddr(payload, to); err != nil {
					return err
				}
				n, from, err := uc.ReadFromAddr(buf)
				if err == nil && (from != to || n != len(payload)) {
					err = fmt.Errorf("ReadFromAddr = %d, %v", n, from)
				}
				return err
			},
		} {
			var ferr error
			allocs := testing.AllocsPerRun(100, func() {
				if err := f(); err != nil {
					ferr = err
				}
			})
			if ferr != nil || allocs != 0 {
				t.Errorf("RelayListen=%v %s: %v allocs per round trip, %v", relayListen, name, allocs, ferr)
			}
		}
	}
}

func TestNewUDPConn(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo) // echoes the header too
	rconn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(echoAP))
	if err != nil {
		t.Fatal(err)
	}
	ctl, peer := net.Pipe()
	c := socks0.NewUDPConn(ctl, rconn, wire.Addr{})
	defer c.Close()
	if c.BoundAddr().IsValid() || c.RelayAddr().String() != echoAP.String() {
		t.Errorf("BoundAddr %v, RelayAddr %v", c.BoundAddr(), c.RelayAddr())
	}
	to := mustAddr("192.0.2.1:7")
	if _, err := c.WriteTo([]byte("loop"), to); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(time.Second))
	if n, from, err := c.ReadFrom(buf); err != nil || string(buf[:n]) != "loop" || from.String() != to.String() {
		t.Fatalf("ReadFrom = %q, %v, %v", buf[:n], from, err)
	}
	peer.Close()
	<-c.Done()
	if !errors.Is(c.Err(), socks0.ErrAssociationClosed) {
		t.Errorf("Err() = %v", c.Err())
	}

	// Close closes the control conn and the relay, also without a relay.
	for _, withRelay := range []bool{true, false} {
		cc, cs := net.Pipe()
		var rc *net.UDPConn
		var relay net.Conn
		if withRelay {
			if rc, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
				t.Fatal(err)
			}
			relay = rc
		}
		if err := socks0.NewUDPConn(cc, relay, wire.Addr{}).Close(); err != nil {
			t.Fatal(err)
		}
		cs.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := cs.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("relay %v: control not closed: %v", withRelay, err)
		}
		if withRelay {
			if _, err := rc.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
				t.Errorf("relay not closed: %v", err)
			}
		}
	}
}

// A UDPConn without a control conn fails every call as a config error.
func TestNewUDPConnInvalid(t *testing.T) {
	u := socks0.NewUDPConn(nil, nil, wire.Addr{})
	if err := u.Err(); socks0.KindOf(err) != socks0.KindConfig || !socks0.IsProxyError(err) {
		t.Errorf("Err() = %v; KindOf %q", err, socks0.KindOf(err))
	}
	for name, f := range map[string]func() error{
		"Read":        func() error { _, err := u.Read(nil); return err },
		"WriteTo":     func() error { _, err := u.WriteTo([]byte("x"), mustAddr("192.0.2.1:9")); return err },
		"WriteToAddr": func() error { _, err := u.WriteToAddr([]byte("x"), mustAddr("192.0.2.1:1")); return err },
		"ReadFrom":    func() error { _, _, err := u.ReadFrom(make([]byte, 1)); return err },
		"SetDeadline": func() error { return u.SetDeadline(time.Now()) },
	} {
		if err := f(); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("%s = %v", name, err)
		}
	}
	if _, err := u.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SyscallConn: %v", err)
	}
	select {
	case <-u.Done():
	default:
		t.Error("Done open")
	}
	if err := u.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if err := u.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("2nd Close = %v", err)
	}
	// (nil, relay): the relay is closed, not leaked.
	rc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := socks0.NewUDPConn(nil, rc, wire.Addr{}).Err(); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("NewUDPConn(nil, relay).Err() = %v", err)
	}
	if _, err := rc.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("relay left open: %v", err)
	}
}

// spoofPC (not a *net.UDPConn) reports datagrams starting "spoof" as from 192.0.2.99.
type spoofPC struct{ net.PacketConn }

func (p spoofPC) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.PacketConn.ReadFrom(b)
	if hn := 10; n >= hn+5 && string(b[hn:hn+5]) == "spoof" {
		a = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 1}
	}
	return n, a, err
}

type plainConn struct{ net.Conn }

// Relays wrapped by RelayListen or RelayDial: still filtered; no SyscallConn.
func TestUDPRelayWrappers(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	var drops atomic.Int32
	trace := &socks0.ClientTrace{DroppedDatagram: func(wire.Addr, error) { drops.Add(1) }}
	t.Run("RelayListen", func(t *testing.T) {
		d := &socks0.Dialer{
			ProxyAddr: listenProxy(t),
			RelayListen: func(ctx context.Context, network, laddr string) (net.PacketConn, error) {
				pc, err := new(net.ListenConfig).ListenPacket(ctx, network, laddr)
				return spoofPC{pc}, err
			},
			Config: &socks0.Config{Trace: trace},
		}
		c := mustDial(t, d, "udp", echoAP.String())
		c.SetWriteDeadline(time.Now().Add(time.Second))
		c.Write([]byte("spoof"))
		if s := roundTrip(t, c, "real"); s != "real" || drops.Load() != 1 {
			t.Errorf("echo %q, %d drops", s, drops.Load())
		}
		if _, err := c.(*socks0.UDPConn).SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("SyscallConn: %v", err)
		}
	})
	t.Run("RelayDial", func(t *testing.T) {
		d := &socks0.Dialer{
			ProxyAddr: listenProxy(t),
			RelayDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := new(net.Dialer).DialContext(ctx, network, addr)
				return plainConn{c}, err
			},
		}
		c := mustDial(t, d, "udp", echoAP.String())
		if s := roundTrip(t, c, "plain"); s != "plain" {
			t.Errorf("echo %q", s)
		}
		if _, err := c.(*socks0.UDPConn).SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("SyscallConn: %v", err)
		}
	})
}

// ICMP port unreachable from the relay is returned, not dropped.
func TestUDPRefused(t *testing.T) {
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.LocalAddr().(*net.UDPAddr)
	dead.Close()
	rconn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	ctl, peer := net.Pipe()
	defer peer.Close()
	c := socks0.NewUDPConn(ctl, rconn, mustAddr("192.0.2.1:53"))
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	var rerr error
	for range 3 { // the error may surface on a later call
		if _, rerr = c.Write([]byte("x")); rerr != nil {
			break
		}
		if _, rerr = c.Read(make([]byte, 8)); rerr != nil {
			break
		}
	}
	if !errors.Is(rerr, eConnRefused) || socks0.KindOf(rerr) != socks0.KindRefused {
		t.Errorf("err = %v; kind %q", rerr, socks0.KindOf(rerr))
	}
}

func TestRequestAssociate(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	conn := netDial(t, "tcp", listenProxy(t))
	var hooks []string
	hook := func(s string) *socks0.ClientTrace {
		return &socks0.ClientTrace{
			GotReply:        func(wire.Reply, wire.Addr) { hooks = append(hooks, s+" reply") },
			RelayDialStart:  func(string, string) {},
			RelayDialDone:   func(string, string, error) {},
			DroppedDatagram: func(wire.Addr, error) {},
			Accepted:        func(wire.Addr, error) {},
		}
	}
	ctx := socks0.WithClientTrace(socks0.WithClientTrace(t.Context(), hook("outer")), hook("inner"))
	bound, err := socks0.Request(ctx, conn, wire.CmdUDPAssociate, mustAddr("0.0.0.0:0"), &socks0.Config{Mode: socks0.ModeEarly})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(hooks, []string{"inner reply", "outer reply"}) {
		t.Errorf("hooks %q", hooks)
	}
	relay := netDial(t, "udp", bound.String())
	c := socks0.NewUDPConn(conn, relay, mustAddr(echoAP.String()))
	defer c.Close()
	if s := roundTrip(t, c, "layer 2"); s != "layer 2" {
		t.Errorf("echo %q", s)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	conn2 := netDial(t, "tcp", listenProxy(t))
	if _, err := socks0.Request(ctx, conn2, 0x7F, mustAddr("0.0.0.0:0"), nil); !errors.Is(err, context.Canceled) || err.(*net.OpError).Op != "socks 0x7f" {
		t.Errorf("canceled Request: %v", err)
	}
}

// A BND the client must not send to (loopback, broadcast, multicast, a private
// address from a public proxy) fails the association; RelayUseProxyHost is the
// way out for a NATed proxy's private BND.
func TestUDPRejectsHostileBND(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	port := uint16(sink.LocalAddr().(*net.UDPAddr).Port)
	bnd := func(s string) wire.Addr { return mustAddr(net.JoinHostPort(s, fmt.Sprint(port))) }
	for _, tc := range []struct {
		proxyIP   string // the proxy's IP (ProxyAddr), reached through ProxyDial
		bnd       wire.Addr
		proxyHost bool
		ok        bool
	}{
		{proxyIP: "192.0.2.10", bnd: bnd("127.0.0.1")},
		{proxyIP: "192.0.2.10", bnd: bnd("::1")},
		{proxyIP: "192.0.2.10", bnd: bnd("::ffff:127.0.0.1")},
		{proxyIP: "192.0.2.10", bnd: bnd("localhost")},
		{proxyIP: "192.0.2.10", bnd: bnd("255.255.255.255")},
		{proxyIP: "192.0.2.10", bnd: bnd("224.0.0.251")},
		{proxyIP: "192.0.2.10", bnd: bnd("ff02::fb")},
		{proxyIP: "192.0.2.10", bnd: bnd("10.1.2.3")},
		{proxyIP: "192.0.2.10", bnd: bnd("100.64.1.1")},
		{proxyIP: "192.0.2.10", bnd: bnd("169.254.169.254")},
		{proxyIP: "192.0.2.10", bnd: bnd("fd00::1")},
		{proxyIP: "10.0.0.5", bnd: bnd("127.0.0.1")},
		{proxyIP: "10.0.0.5", bnd: bnd("169.254.169.254")},
		{proxyIP: "192.0.2.10", bnd: bnd("10.1.2.3"), proxyHost: true, ok: true},
		{proxyIP: "192.0.2.10", bnd: bnd("0.0.0.0"), ok: true},
		{proxyIP: "192.0.2.10", bnd: bnd("198.51.100.7"), ok: true},
		{proxyIP: "10.0.0.5", bnd: bnd("192.168.1.1"), ok: true},
		{proxyIP: "127.0.0.1", bnd: bnd("10.1.2.3"), ok: true},
		{proxyIP: "127.0.0.1", bnd: bnd("127.0.0.1"), ok: true},
	} {
		proxy := listen(t, answer(must(wire.AppendReply(nil, wire.ReplySucceeded, tc.bnd)), nil, true))
		d := &socks0.Dialer{
			ProxyAddr: net.JoinHostPort(tc.proxyIP, "1080"),
			ProxyDial: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, n, proxy)
			},
			RelayUseProxyHost: tc.proxyHost,
		}
		c, err := d.DialContext(t.Context(), "udp", "9.9.9.9:53")
		switch {
		case tc.ok && err != nil:
			t.Errorf("proxy %s, BND %v: %v", tc.proxyIP, tc.bnd, err)
		case tc.ok:
			c.Close()
		case err == nil:
			c.Write([]byte("private-dns-query"))
			c.Close()
			t.Errorf("proxy %s, BND %v: association opened", tc.proxyIP, tc.bnd)
		default:
			he, _ := errors.AsType[*socks0.HandshakeError](err)
			if he == nil || he.Stage != socks0.StageRelayDial || socks0.KindOf(err) != socks0.KindDenied ||
				!errors.Is(err, socks0.ErrNotAllowed) || !strings.Contains(err.Error(), "relay address refused") {
				t.Errorf("proxy %s, BND %v: %v (kind %s)", tc.proxyIP, tc.bnd, err, socks0.KindOf(err))
			}
		}
	}
	sink.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := sink.ReadFrom(make([]byte, 100)); err == nil {
		t.Fatalf("a %d-byte datagram reached the client's loopback service", n)
	}
}

// With AssociateLocalPort, DST.PORT is the relay socket's port, so the server
// drops datagrams forged from another port.
func TestUDPAssociateLocalPort(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	var (
		mu    sync.Mutex
		dst   wire.Addr
		drops []string
	)
	s := &server.Server{
		Handler: &server.AssociateHandler{Filter: server.AllowAll},
		Trace: &server.ServerTrace{
			GotRequest: func(_ context.Context, r *server.Request) { mu.Lock(); dst = r.Addr; mu.Unlock() },
			Dropped: func(_ context.Context, from netip.AddrPort, err error) {
				mu.Lock()
				drops = append(drops, err.Error())
				mu.Unlock()
			},
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	defer s.Close()
	for _, listen := range []bool{false, true} {
		d := &socks0.Dialer{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true}
		if listen {
			d.RelayListen = new(net.ListenConfig).ListenPacket
		}
		c := mustDial(t, d, "udp", echoAP.String())
		uc := c.(*socks0.UDPConn)
		lport := uc.LocalAddr().(*net.UDPAddr).Port
		mu.Lock()
		got := dst
		mu.Unlock()
		if !got.IP().IsUnspecified() || int(got.Port()) != lport {
			t.Fatalf("RelayListen %v: DST %v, relay socket port %d", listen, got, lport)
		}
		attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(echoAP))
		attacker.WriteToUDPAddrPort(append(h, "forged"...), uc.RelayAddr().(*net.UDPAddr).AddrPort())
		attacker.Close()
		time.Sleep(50 * time.Millisecond)
		if s := roundTrip(t, c, "hi"); s != "hi" {
			t.Fatalf("echo %q", s)
		}
		c.Close()
		mu.Lock()
		if len(drops) != 1 || !strings.Contains(drops[0], "another source") {
			t.Fatalf("drops %q", drops)
		}
		drops = nil
		mu.Unlock()
	}
	// RelayListen failures fail the association before the request.
	errListen := errors.New("listen failed")
	for _, l := range []func(context.Context, string, string) (net.PacketConn, error){
		func(context.Context, string, string) (net.PacketConn, error) { return nil, errListen },
		func(context.Context, string, string) (net.PacketConn, error) { return nil, nil },
		func(ctx context.Context, n, a string) (net.PacketConn, error) {
			pc, err := new(net.ListenConfig).ListenPacket(ctx, n, a)
			return pc, errors.Join(err, errListen)
		},
		func(context.Context, string, string) (net.PacketConn, error) { return pipePacketConn{}, nil },
	} {
		d := &socks0.Dialer{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true, RelayListen: l}
		if _, err := d.DialContext(t.Context(), "udp", echoAP.String()); handshakeErrOf(t, err).Stage != socks0.StageRelayDial {
			t.Errorf("RelayListen failing: %v", err)
		}
	}
	// Not with RelayDial or an explicit DST: nothing to bind first.
	for _, d := range []*socks0.Dialer{
		{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true, RelayDial: new(net.Dialer).DialContext},
		{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true, AssociateAddr: "192.0.2.1:0"},
	} {
		if _, err := d.DialContext(t.Context(), "udp", echoAP.String()); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("%+v: %v", d, err)
		}
	}
}

type pipePacketConn struct{ net.PacketConn }

func (pipePacketConn) LocalAddr() net.Addr { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (pipePacketConn) Close() error        { return nil }
