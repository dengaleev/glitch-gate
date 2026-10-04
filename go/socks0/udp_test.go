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
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	_ net.Conn       = (*socks0.UDPConn)(nil)
	_ net.PacketConn = (*socks0.UDPConn)(nil)
	_ syscall.Conn   = (*socks0.UDPConn)(nil)
)

func roundTrip(t testing.TB, c net.Conn, msg string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestUDPDial(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	for _, mode := range modes {
		for _, target := range []string{echoAP.String(), fmt.Sprintf("localhost:%d", echoAP.Port())} {
			t.Run(mode.String()+"/"+target, func(t *testing.T) {
				got := make(chan wire.Addr, 1)
				raw := make(chan []byte, 1)
				conns := make(chan *recConn, 1)
				d := &socks0.Dialer{
					ProxyAddr: listen(t, udpProxy{got: got, raw: raw}.serve),
					ProxyDial: recDial(conns),
					Config:    &socks0.Config{Mode: mode},
				}
				c, err := d.DialContext(t.Context(), "udp", target)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				uc := c.(*socks0.UDPConn)
				if s := roundTrip(t, c, "ping"); s != "ping" {
					t.Fatalf("echo %q", s)
				}
				if dst := <-got; dst != mustAddr("0.0.0.0:0") {
					t.Errorf("DST %v", dst)
				}
				d0 := <-raw
				if want := wire.UDPHeaderLen(mustAddr(target)) + 4; len(d0) != want {
					t.Errorf("datagram of %d bytes, want %d", len(d0), want)
				}
				writes, _, _ := (<-conns).snapshot()
				if want := map[socks0.Mode]int{socks0.ModeSequential: 2}[mode]; len(writes) != max(want, 1) {
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
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve)}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	uc := pc.(*socks0.UDPConn)
	pc.SetDeadline(time.Now().Add(2 * time.Second))
	if pc.(net.Conn).RemoteAddr() != nil {
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

	isOp := func(err error, op string, target error) {
		t.Helper()
		oe, ok := err.(*net.OpError)
		if !ok || oe.Op != op || oe.Net != "udp" || !errors.Is(err, target) {
			t.Errorf("err = %#v; want *net.OpError{Op: %s} matching %v", err, op, target)
		}
	}
	for _, bad := range []net.Addr{&net.TCPAddr{}, nil, (*net.UDPAddr)(nil), &net.UDPAddr{}, (*wire.Addr)(nil), wire.Addr{}} {
		_, err := pc.WriteTo([]byte("x"), bad)
		isOp(err, "write", syscall.EINVAL)
	}
	_, err = uc.WriteToAddr([]byte("x"), wire.Addr{})
	isOp(err, "write", syscall.EINVAL)
	_, err = uc.Write([]byte("x"))
	isOp(err, "write", eDestAddrReq)

	// udp4 restricts targets, not names.
	pc4, err := d.ListenPacket(t.Context(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc4.Close()
	_, err = pc4.WriteTo([]byte("x"), mustAddr("[2001:db8::1]:53"))
	if _, ok := errors.AsType[*net.AddrError](err); !ok {
		t.Errorf("udp4 to IPv6: %v", err)
	}
	if _, err := pc4.WriteTo([]byte("x"), mustAddr("example.com:53")); err != nil {
		t.Errorf("udp4 to a name: %v", err)
	}
}

func TestUDPConnected(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve)}
	c, err := d.DialContext(t.Context(), "udp4", echoAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uc := c.(*socks0.UDPConn)
	_, err = uc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(echoAP))
	if oe, ok := err.(*net.OpError); !ok || oe.Err != net.ErrWriteToConnected {
		t.Errorf("WriteTo on a connected conn: %#v", err)
	}
	if _, err := uc.WriteToAddr([]byte("x"), mustAddr(echoAP.String())); !errors.Is(err, net.ErrWriteToConnected) {
		t.Errorf("WriteToAddr on a connected conn: %v", err)
	}
	// Truncation: as a Unix UDP socket, no error.
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, from, err := uc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "0123" || from.String() != echoAP.String() {
		t.Fatalf("truncated ReadFrom = %q, %v, %v", buf[:n], from, err)
	}
}

func TestUDPMessageSize(t *testing.T) {
	for _, tt := range []struct {
		network, target string
		max             int
	}{
		{"udp4", "192.0.2.1:9", 65535 - 8 - 20 - 10},
		{"udp4", "[2001:db8::1]:9", 65535 - 8 - 20 - 22},
		{"udp6", "192.0.2.1:9", 65535 - 8 - 10},
		{"udp4", "example.com:9", 65535 - 8 - 20 - 18},
	} {
		t.Run(tt.network+"/"+tt.target, func(t *testing.T) {
			if tt.network == "udp6" && !hasIPv6() {
				t.Skip("no IPv6 loopback")
			}
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{network: tt.network}.serve)}
			pc, err := d.ListenPacket(t.Context(), "udp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			to := mustAddr(tt.target)
			if _, err := pc.WriteTo(make([]byte, tt.max+1), to); !errors.Is(err, eMsgSize) {
				t.Errorf("payload %d: %v; want EMSGSIZE", tt.max+1, err)
			}
			// The limit itself passes the check; the kernel may still refuse it.
			if _, err := pc.WriteTo(make([]byte, tt.max), to); err != nil && !errors.Is(err, eMsgSize) && !errors.Is(err, eNoBufs) {
				t.Errorf("payload %d: %v", tt.max, err)
			}
			if _, err := pc.WriteTo(make([]byte, 1200), to); err != nil {
				t.Errorf("payload 1200: %v", err)
			}
		})
	}
}

func hasIPv6() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		ln.Close()
	}
	return err == nil
}

func TestUDPDropped(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	assoc := make(chan *association, 1)
	type drop struct {
		from wire.Addr
		err  error
	}
	var mu sync.Mutex
	var drops []drop
	d := &socks0.Dialer{
		ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve),
		Config: &socks0.Config{Trace: &socks0.ClientTrace{DroppedDatagram: func(from wire.Addr, err error) {
			mu.Lock()
			drops = append(drops, drop{from, err})
			mu.Unlock()
		}}},
	}
	c, err := d.DialContext(t.Context(), "udp", echoAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a := <-assoc
	if s := roundTrip(t, c, "first"); s != "first" { // the server learns our address
		t.Fatal(s)
	}
	other := mustAddr("192.0.2.7:53")
	hdr := func(frag uint8, a wire.Addr) []byte { b, _ := wire.AppendUDPHeader(nil, frag, a); return b }
	target := mustAddr(echoAP.String())
	junk := [][]byte{
		append(hdr(1, target), "fragment"...),
		append(hdr(0, other), "wrong source"...),
		{0, 0, 0, 9, 1, 2, 3},
		{0, 0, 0, 1, 127},
		append(hdr(0, target), "good"...),
	}
	for _, b := range junk {
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
	if len(got) != 4 {
		t.Fatalf("drops %v", got)
	}
	if got[0].from != target || got[0].err != socks0.ErrFragment {
		t.Errorf("drop 0: %v", got[0])
	}
	if got[1].from != other || got[1].err != socks0.ErrWrongSource {
		t.Errorf("drop 1: %v", got[1])
	}
	for _, dr := range got[2:] {
		pe, ok := errors.AsType[*socks0.ProtocolError](dr.err)
		if !ok || pe.Stage != wire.StageUDPHeader || dr.from.IsValid() {
			t.Errorf("drop: %v, %#v", dr.from, dr.err)
		}
	}
	// Only junk: the deadline still applies across dropped datagrams.
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 10 {
			a.send(t, junk[0])
			time.Sleep(10 * time.Millisecond)
		}
	})
	start := time.Now()
	_, err = c.Read(buf)
	wg.Wait()
	if !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || time.Since(start) > time.Second {
		t.Errorf("Read = %v after %v", err, time.Since(start))
	}
	if oe, ok := err.(*net.OpError); !ok || !oe.Timeout() || oe.Op != "read" {
		t.Errorf("err %#v", err)
	}
}

func TestUDPAssociateDST(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	relayDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, addr)
	}
	for _, tt := range []struct {
		name      string
		assoc     string // AssociateAddr (DialContext)
		listen    *string
		relayDial bool
		want      string // DST; "" for a config error
	}{
		{name: "default", want: "0.0.0.0:0"},
		{name: "AssociateAddr", assoc: "192.0.2.9:0", want: "192.0.2.9:0"},
		{name: "AssociateAddr port", assoc: "192.0.2.9:4000"},
		{name: "AssociateAddr port RelayDial", assoc: "192.0.2.9:4000", relayDial: true, want: "192.0.2.9:4000"},
		{name: "AssociateAddr bad", assoc: "nope"},
		{name: "listen empty", listen: new(""), want: "0.0.0.0:0"},
		{name: "listen :0", listen: new(":0"), want: "0.0.0.0:0"},
		{name: "listen [::]:0", listen: new("[::]:0"), want: "0.0.0.0:0"},
		{name: "listen overrides", assoc: "192.0.2.9:0", listen: new("198.51.100.1:0"), want: "198.51.100.1:0"},
		{name: "listen port", listen: new("198.51.100.1:53")},
		{name: "listen port RelayDial", listen: new("198.51.100.1:53"), relayDial: true, want: "198.51.100.1:53"},
		{name: "listen bad", listen: new("198.51.100.1")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan wire.Addr, 1)
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{got: got}.serve), AssociateAddr: tt.assoc}
			if tt.relayDial {
				d.RelayDial = relayDial
			}
			var c io.Closer
			var err error
			if tt.listen != nil {
				c, err = d.ListenPacket(t.Context(), "udp", *tt.listen)
			} else {
				c, err = d.DialContext(t.Context(), "udp", echoAP.String())
			}
			if tt.want == "" {
				if socks0.KindOf(err) != socks0.KindConfig || handshakeErrOf(t, err).Stage != socks0.StageConfig {
					t.Fatalf("err = %v; want a config error", err)
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

func TestUDPRelayAddr(t *testing.T) {
	v6 := hasIPv6()
	unspec4 := func(ap netip.AddrPort) wire.Addr {
		return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port()))
	}
	unspec6 := func(ap netip.AddrPort) wire.Addr {
		return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), ap.Port()))
	}
	private := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("10.255.255.1:%d", ap.Port())) }
	name := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("localhost:%d", ap.Port())) }
	chain := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, addr)
	}
	for _, tt := range []struct {
		name       string
		relay      string // relay network
		listen     string // proxy listener: "tcp4" (127.0.0.1) or "tcp6"
		host       string // ProxyAddr host
		bnd        func(netip.AddrPort) wire.Addr
		chain      bool
		relayDial  bool
		proxyHost  bool
		wantNet    string
		wantHost   string // relay dialed at wantHost:BND.PORT
		roundTrip  bool
		needsIPv6  bool
		needsLocal bool // localhost resolves to 127.0.0.1 and ::1
	}{
		{name: "BND as is", bnd: nil, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true},
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
		{name: "0.0.0.0 over IPv6 control", listen: "tcp6", host: "localhost", bnd: unspec4, wantNet: "udp4", wantHost: "127.0.0.1", roundTrip: true, needsLocal: true},
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
			echoAP := udpServe(t, cmp.Or(tt.relay, "udp4"), echo)
			addr := listenOn(t, cmp.Or(tt.listen, "tcp4"), udpProxy{network: tt.relay, bnd: tt.bnd}.serve)
			_, port, _ := net.SplitHostPort(addr)
			var dialed []string
			d := &socks0.Dialer{
				ProxyAddr:         net.JoinHostPort(cmp.Or(tt.host, "127.0.0.1"), port),
				RelayUseProxyHost: tt.proxyHost,
				Config: &socks0.Config{Trace: &socks0.ClientTrace{
					RelayDialStart: func(network, addr string) { dialed = append(dialed, network, addr) },
				}},
			}
			if tt.chain {
				d.ProxyDial = chain
			}
			if tt.relayDial {
				d.RelayDial = chain
			}
			c, err := d.DialContext(t.Context(), "udp", echoAP.String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			uc := c.(*socks0.UDPConn)
			want := []string{tt.wantNet, net.JoinHostPort(tt.wantHost, fmt.Sprint(uc.BoundAddr().Port()))}
			if !slices.Equal(dialed, want) {
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

func listenOn(t testing.TB, network string, handle func(net.Conn)) string {
	t.Helper()
	if network == "tcp4" {
		return listen(t, handle)
	}
	ln, err := net.Listen(network, "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { defer c.Close(); handle(c) })
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

func TestUDPBNDPortZero(t *testing.T) {
	zero := func(netip.AddrPort) wire.Addr { return mustAddr("127.0.0.1:0") }
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{bnd: zero}.serve), Config: &socks0.Config{Mode: mode}}
			_, err := d.ListenPacket(t.Context(), "udp", "")
			he := handshakeErrOf(t, err)
			pe, ok := errors.AsType[*socks0.ProtocolError](err)
			if !ok || pe.Field != wire.FieldPORT || he.Stage != wire.StageReply || socks0.KindOf(err) != socks0.KindProtocol {
				t.Errorf("err = %v", err)
			}
			if oe := err.(*net.OpError); oe.Op != "socks udp associate" {
				t.Errorf("Op %q", oe.Op)
			}
		})
	}
}

func TestUDPRelayListen(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	listenUDP := func(ctx context.Context, network, laddr string) (net.PacketConn, error) {
		return new(net.ListenConfig).ListenPacket(ctx, network, laddr)
	}
	// A NAT-like proxy answers from another port: only RelayListen sees it.
	for _, unconnected := range []bool{false, true} {
		t.Run(fmt.Sprint("RelayListen=", unconnected), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{nat: true}.serve)}
			if unconnected {
				d.RelayListen = listenUDP
			}
			c, err := d.DialContext(t.Context(), "udp", echoAP.String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			uc := c.(*socks0.UDPConn)
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			c.Write([]byte("nat"))
			buf := make([]byte, 16)
			n, err := c.Read(buf)
			if unconnected {
				if err != nil || string(buf[:n]) != "nat" {
					t.Fatalf("Read = %q, %v", buf[:n], err)
				}
				if uc.RelayAddr().String() != uc.BoundAddr().String() {
					t.Errorf("RelayAddr %v", uc.RelayAddr())
				}
			} else if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("connected relay: Read = %q, %v; want a timeout", buf[:n], err)
			}
		})
	}
	t.Run("both", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1", RelayListen: listenUDP, RelayDial: new(net.Dialer).DialContext}
		_, err := d.ListenPacket(t.Context(), "udp", "")
		if socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("err = %v", err)
		}
	})
}

func TestUDPLifetime(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	for _, how := range []string{"close", "reset"} {
		t.Run(how, func(t *testing.T) {
			assoc := make(chan *association, 1)
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
			c, err := d.DialContext(t.Context(), "udp", echoAP.String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			uc := c.(*socks0.UDPConn)
			a := <-assoc
			read := make(chan error, 1)
			go func() {
				_, err := c.Read(make([]byte, 16))
				read <- err
			}()
			time.Sleep(20 * time.Millisecond)
			if how == "reset" {
				a.control.(*net.TCPConn).SetLinger(0)
			}
			a.control.Close()
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
				if !errors.Is(err, socks0.ErrAssociationClosed) || socks0.KindOf(err) != socks0.KindAssociation {
					t.Errorf("err = %v; want ErrAssociationClosed", err)
				}
				if how == "close" && !errors.Is(err, io.EOF) || how == "reset" && !errors.Is(err, eConnReset) && !errors.Is(err, io.EOF) {
					t.Errorf("err = %v; want the control conn's error wrapped", err)
				}
			}
			if oe, ok := rerr.(*net.OpError); !ok || oe.Op != "read" || oe.Net != "udp" {
				t.Errorf("read error %#v", rerr)
			}
			if err := c.Close(); err != nil {
				t.Errorf("Close after the proxy ended: %v", err)
			}
			if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
				t.Errorf("Write after Close: %v", err)
			}
		})
	}
}

func TestUDPClose(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	assoc := make(chan *association, 4)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	base := runtime.NumGoroutine()
	c, err := d.DialContext(t.Context(), "udp", echoAP.String())
	if err != nil {
		t.Fatal(err)
	}
	uc := c.(*socks0.UDPConn)
	a := <-assoc
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			buf := make([]byte, 16)
			for {
				if _, err := c.Read(buf); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("Read: %v", err)
					}
					return
				}
			}
		})
		wg.Go(func() {
			for {
				if _, err := c.Write([]byte("x")); err != nil {
					if !errors.Is(err, net.ErrClosed) {
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
	if !errors.Is(uc.Err(), net.ErrClosed) || socks0.KindOf(uc.Err()) != socks0.KindClosed {
		t.Errorf("Err() = %v", uc.Err())
	}
	<-a.ended
	waitGoroutines(t, base)
}

func waitGoroutines(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, want %d:\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUDPCleanup(t *testing.T) {
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	base := runtime.NumGoroutine()
	func() {
		pc, err := d.ListenPacket(t.Context(), "udp", "")
		if err != nil {
			t.Fatal(err)
		}
		_ = pc // leaked
	}()
	a := <-assoc
	for range 200 {
		runtime.GC()
		select {
		case <-a.ended:
			waitGoroutines(t, base)
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("leaked UDPConn not cleaned up")
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
		{name: "unknown network", d: socks0.Dialer{}, stage: socks0.StageConfig, kind: socks0.KindConfig},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var events []string
			d := tt.d
			d.ProxyAddr = listen(t, tt.p.serve)
			d.Config = &socks0.Config{Trace: &socks0.ClientTrace{
				RelayDialStart: func(network, addr string) { events = append(events, "start "+network) },
				RelayDialDone:  func(network, addr string, err error) { events = append(events, fmt.Sprint("done ", err != nil)) },
				HandshakeDone:  func(err error) { events = append(events, fmt.Sprint("handshake ", err != nil)) },
			}}
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
			if tt.stage == socks0.StageRelayDial && !slices.Equal(events, []string{"start udp4", "done true", "handshake true"}) {
				t.Errorf("trace %q", events)
			}
		})
	}
}

func TestUDPCancel(t *testing.T) {
	hang := listen(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	d := &socks0.Dialer{ProxyAddr: hang}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)
	_, err := d.DialContext(ctx, "udp", "192.0.2.1:53")
	if !errors.Is(err, context.Canceled) || handshakeErrOf(t, err).Stage != wire.StageMethodSelection {
		t.Errorf("err = %v", err)
	}
}

func TestUDPResolver(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.53")
	for _, tc := range []bool{false, true} {
		t.Run(fmt.Sprint("truncated=", tc), func(t *testing.T) {
			dnsUDP := udpServe(t, "udp4", dnsAnswer(want, tc))
			tcpAddr := dnsTCP(t, dnsAnswer(want, false))
			var nets []string
			var mu sync.Mutex
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve)}
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
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve), Config: &socks0.Config{Mode: socks0.ModeEarly}}
	var dialer func(localAddress, remoteAddress string) (net.Conn, error) = dialCtx(t.Context(), d.DialContext, "udp")
	c, err := dialer("", ntpd.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := make([]byte, 48)
	q[0] = 0x23
	copy(q[40:], "transmit")
	r := roundTrip(t, c, string(q))
	if len(r) != 48 || r[24:32] != "transmit" {
		t.Errorf("answer % x", r)
	}
}

func TestUDPChained(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	outer := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve)}
	inner := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve), RelayDial: outer.DialContext}
	c, err := inner.DialContext(t.Context(), "udp", echoAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if s := roundTrip(t, c, "nested"); s != "nested" {
		t.Errorf("echo %q", s)
	}
	if _, err := c.(*socks0.UDPConn).SyscallConn(); err != nil {
		t.Errorf("SyscallConn over a UDPConn relay: %v", err)
	}
}

func TestUDPSyscallConn(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve)}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	rc, err := pc.(*socks0.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fdOK bool
	if err := rc.Control(func(fd uintptr) { fdOK = fd > 0 }); err != nil || !fdOK {
		t.Errorf("Control: %v", err)
	}
}

func TestUDPAllocs(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	newConn := func(target wire.Addr) *socks0.UDPConn {
		rconn, err := net.DialUDP("udp4", nil, relay.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		ctl, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		c := socks0.NewUDPConn(ctl, rconn, target)
		t.Cleanup(func() { c.Close() })
		return c
	}
	target := mustAddr("192.0.2.1:53")
	payload, in, buf := make([]byte, 512), make([]byte, 2048), make([]byte, 2048)
	answer := func() { // echo, header included
		n, from, err := relay.ReadFromUDPAddrPort(in)
		if err == nil {
			_, err = relay.WriteToUDPAddrPort(in[:n], from)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	connected, unconnected := newConn(target), newConn(wire.Addr{})
	for _, tt := range []struct {
		name string
		f    func() error
	}{
		{"Write+Read", func() error {
			if _, err := connected.Write(payload); err != nil {
				return err
			}
			answer()
			_, err := connected.Read(buf)
			return err
		}},
		{"WriteToAddr+ReadFromAddr", func() error {
			if _, err := unconnected.WriteToAddr(payload, target); err != nil {
				return err
			}
			answer()
			n, from, err := unconnected.ReadFromAddr(buf)
			if err == nil && (from != target || n != len(payload)) {
				err = fmt.Errorf("ReadFromAddr = %d, %v", n, from)
			}
			return err
		}},
	} {
		var ferr error
		allocs := testing.AllocsPerRun(200, func() {
			if err := tt.f(); err != nil {
				ferr = err
			}
		})
		if ferr != nil {
			t.Fatal(ferr)
		}
		if allocs != 0 {
			t.Errorf("%s: %v allocs", tt.name, allocs)
		}
	}
}

func TestNewUDPConn(t *testing.T) {
	echoAP := udpServe(t, "udp4", func(b []byte) []byte { return b }) // echoes the header too
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
}

func TestUDPZero(t *testing.T) {
	c := socks0.NewUDPConn(nil, nil, wire.Addr{})
	if _, err := c.Read(nil); err == nil {
		t.Error("Read: no error")
	}
	if _, err := c.WriteToAddr([]byte("x"), mustAddr("192.0.2.1:1")); err == nil {
		t.Error("WriteToAddr: no error")
	}
	if err := c.SetDeadline(time.Time{}); err == nil {
		t.Error("SetDeadline: no error")
	}
	if _, err := c.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SyscallConn: %v", err)
	}
	<-c.Done()
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
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

func TestUDPRelayWrappers(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	var drops atomic.Int32
	trace := &socks0.ClientTrace{DroppedDatagram: func(wire.Addr, error) { drops.Add(1) }}
	t.Run("RelayListen", func(t *testing.T) {
		d := &socks0.Dialer{
			ProxyAddr: listen(t, udpProxy{}.serve),
			RelayListen: func(ctx context.Context, network, laddr string) (net.PacketConn, error) {
				pc, err := new(net.ListenConfig).ListenPacket(ctx, network, laddr)
				return spoofPC{pc}, err
			},
			Config: &socks0.Config{Trace: trace},
		}
		c, err := d.DialContext(t.Context(), "udp", echoAP.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
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
			ProxyAddr: listen(t, udpProxy{}.serve),
			RelayDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := new(net.Dialer).DialContext(ctx, network, addr)
				return plainConn{c}, err
			},
		}
		c, err := d.DialContext(t.Context(), "udp", echoAP.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if s := roundTrip(t, c, "plain"); s != "plain" {
			t.Errorf("echo %q", s)
		}
		if _, err := c.(*socks0.UDPConn).SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("SyscallConn: %v", err)
		}
	})
}

func TestUDPReadFromName(t *testing.T) {
	assoc := make(chan *association, 1)
	echoAP := udpServe(t, "udp4", echo)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	a := <-assoc
	pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(echoAP)) // the server learns our address
	from := mustAddr("example.com:53")
	hdr, _ := wire.AppendUDPHeader(nil, 0, from)
	a.send(t, append(hdr, "named"...))
	pc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) == "named" {
			if addr != net.Addr(from) {
				t.Errorf("from %#v", addr)
			}
			break
		}
	}
	pc6, err := d.ListenPacket(t.Context(), "udp6", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc6.Close()
	if _, err := pc6.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(echoAP)); err == nil {
		t.Error("udp6 to IPv4: no error")
	}
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
	conn, err := net.Dial("tcp", listen(t, udpProxy{}.serve))
	if err != nil {
		t.Fatal(err)
	}
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
	relay, err := net.Dial("udp", bound.String())
	if err != nil {
		t.Fatal(err)
	}
	c := socks0.NewUDPConn(conn, relay, mustAddr(echoAP.String()))
	defer c.Close()
	if s := roundTrip(t, c, "layer 2"); s != "layer 2" {
		t.Errorf("echo %q", s)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	conn2, err := net.Dial("tcp", listen(t, udpProxy{}.serve))
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if _, err := socks0.Request(ctx, conn2, 0x7F, mustAddr("0.0.0.0:0"), nil); !errors.Is(err, context.Canceled) || err.(*net.OpError).Op != "socks 0x7f" {
		t.Errorf("canceled Request: %v", err)
	}
}

func TestUDPAllocsDialer(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	for _, listen := range []bool{false, true} {
		d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
		if listen {
			d.RelayListen = new(net.ListenConfig).ListenPacket
		}
		c, err := d.DialContext(t.Context(), "udp", echoAP.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		payload, buf := make([]byte, 256), make([]byte, 512)
		roundTrip(t, c, "warm up")
		allocs := testing.AllocsPerRun(100, func() {
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(buf); err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Errorf("RelayListen=%v: %v allocs per round trip", listen, allocs)
		}
	}
}

func listenProxy(t *testing.T) string { return listen(t, udpProxy{}.serve) }
