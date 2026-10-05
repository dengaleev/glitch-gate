package server_test

// UDP ASSOCIATE: the relay, its source lock, filtering, drops, limits and lifetime.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func udpServer() *server.Server {
	s := withHandler(&server.Mux{Associate: &server.AssociateHandler{Filter: server.AllowAll, Resolver: fakeDNS{"echo.test": "127.0.0.1"}}})
	return s
}

func TestInteropUDP(t *testing.T) {
	e1, e2 := echoUDP(t, "127.0.0.1:0"), echoUDP(t, "127.0.0.1:0")
	for _, m := range modes {
		t.Run(m.String(), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: serve(t, udpServer()), Config: &socks0.Config{Mode: m}}
			c, err := d.DialContext(t.Context(), "udp", e1.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			for _, msg := range []string{"ping", "pong", string(payload()[:1400])} {
				if _, err := c.Write([]byte(msg)); err != nil {
					t.Fatal(err)
				}
				expect(t, c, []byte(msg))
			}

			pc, err := d.ListenPacket(t.Context(), "udp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			for _, e := range []*net.UDPConn{e1, e2} {
				if _, err := pc.WriteTo([]byte("to "+e.LocalAddr().String()), e.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 100)
				n, from, err := pc.ReadFrom(b)
				if err != nil || string(b[:n]) != "to "+e.LocalAddr().String() || from.String() != e.LocalAddr().String() {
					t.Fatalf("ReadFrom %q from %v, %v", b[:n], from, err)
				}
			}
			_, port, _ := net.SplitHostPort(e1.LocalAddr().String())
			if _, err := pc.WriteTo([]byte("named"), mustAddr("echo.test:"+port)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 100)
			if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != "named" {
				t.Fatalf("named: %q, %v", b[:n], err)
			}
		})
	}
}

func TestInteropUDPControlClose(t *testing.T) {
	noLeaks(t)
	s := udpServer()
	ended := make(chan error, 1)
	s.Trace = &server.ServerTrace{Done: func(_ context.Context, _ *server.Request, _ server.ConnStats, err error) { ended <- err }}
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	select {
	case err := <-ended:
		if err != nil {
			t.Fatalf("association ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("association outlived its control conn")
	}
}

// The first datagram locks the client's source; a DST with the client's IP, or 0.0.0.0 and its
// port, locks it from the start, so a forged first datagram cannot win; a DST with another IP is
// ignored: the relay cannot be pointed at a victim.
func TestUDPSourceLock(t *testing.T) {
	e := echoUDP(t, "127.0.0.1:0")
	to := apOf(e.LocalAddr())
	t.Run("first datagram", func(t *testing.T) {
		d := &drops{}
		_, relay := assoc(t, serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll}, d)), "0.0.0.0:0")
		a, b := udpSock(t), udpSock(t)
		_, _ = a.WriteTo(dgram(to, "from a"), relay)
		if got := recv(a, 5*time.Second); !bytes.HasSuffix(got, []byte("from a")) {
			t.Fatalf("a: %q", got)
		}
		_, _ = b.WriteTo(dgram(to, "from b"), relay)
		d.wait(t, server.ErrWrongSource)
		if got := recv(b, 100*time.Millisecond); got != nil {
			t.Fatalf("b got %q", got)
		}
	})
	for _, dst := range []string{"own IP", "0.0.0.0"} {
		t.Run("DST "+dst, func(t *testing.T) {
			d := &drops{}
			proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll}, d))
			victim, attacker := udpSock(t), udpSock(t)
			host := "0.0.0.0"
			if dst == "own IP" {
				host = "127.0.0.1"
			}
			_, relay := assoc(t, proxy, net.JoinHostPort(host, strconv.Itoa(victim.LocalAddr().(*net.UDPAddr).Port)))
			_, _ = attacker.WriteTo(dgram(to, "forged first"), relay)
			if got := recv(attacker, 200*time.Millisecond); got != nil {
				t.Fatalf("attacker got %q", got)
			}
			_, _ = victim.WriteTo(dgram(to, "first"), relay)
			if got := recv(victim, 2*time.Second); !bytes.HasSuffix(got, []byte("first")) {
				t.Fatalf("victim: %q", got)
			}
			if ds := d.list(); len(ds) != 1 || !strings.Contains(ds[0], "another source") {
				t.Fatalf("drops %q", ds)
			}
		})
	}
	t.Run("DST other IP", func(t *testing.T) {
		a := udpSock(t)
		_, relay := assoc(t, serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll}, nil)), "192.0.2.1:"+strconv.Itoa(int(apOf(a.LocalAddr()).Port())))
		_, _ = a.WriteTo(dgram(to, "a2"), relay)
		if got := recv(a, 5*time.Second); !bytes.HasSuffix(got, []byte("a2")) {
			t.Fatalf("a: %q", got)
		}
	})
}

func TestUDPFiltering(t *testing.T) {
	for _, tt := range []struct {
		mode     server.Filtering
		samePeer bool // another socket on the target's IP reaches the client
	}{
		{server.AddressAndPortDependent, false},
		{server.AddressDependent, true},
		{server.EndpointIndependent, true},
	} {
		t.Run(strconv.Itoa(int(tt.mode)), func(t *testing.T) {
			d := &drops{}
			proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll, Filtering: tt.mode}, d))
			_, relay := assoc(t, proxy, "0.0.0.0:0")
			client := udpSock(t)
			target, tsrc := spyUDP(t)
			_, _ = client.WriteTo(dgram(apOf(target.LocalAddr()), "hello"), relay)
			var relayOut netip.AddrPort
			select {
			case relayOut = <-tsrc:
			case <-time.After(5 * time.Second):
				t.Fatal("target got nothing")
			}
			// The contacted target is always delivered, its address in the header.
			_, _ = target.WriteToUDPAddrPort([]byte("answer"), relayOut)
			if got := recv(client, 5*time.Second); !bytes.Equal(got, dgram(apOf(target.LocalAddr()), "answer")) {
				t.Fatalf("answer: %x", got)
			}
			other := udpSock(t)
			_, _ = other.WriteToUDPAddrPort([]byte("unsolicited"), relayOut)
			got := recv(client, 200*time.Millisecond)
			if (got != nil) != tt.samePeer {
				t.Fatalf("unsolicited delivered=%v", got != nil)
			}
			if !tt.samePeer {
				d.wait(t, server.ErrUnsolicited)
			}
		})
	}
}

func TestUDPDrops(t *testing.T) {
	e := echoUDP(t, "127.0.0.1:0")
	big := udpSock(t)
	d := &drops{}
	const maxDgram = 200
	proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll, MaxDatagram: maxDgram}, d))
	_, relay := assoc(t, proxy, "0.0.0.0:0")
	c := udpSock(t)
	to := apOf(e.LocalAddr())
	_, _ = c.WriteTo(dgram(to, "lock"), relay)
	recv(c, 5*time.Second)
	for _, tt := range []struct {
		name string
		b    []byte
		want error
	}{
		{"frag", append([]byte{0, 0, 1}, dgram(to, "x")[3:]...), server.ErrFragment},
		{"atyp", []byte{0, 0, 0, 9, 1, 2, 3}, &wire.ProtocolError{}},
		{"truncated", dgram(to, "")[:7], &wire.ProtocolError{}},
		{"too large", dgram(to, string(make([]byte, maxDgram))), server.ErrTooLarge},
	} {
		_, _ = c.WriteTo(tt.b, relay)
		d.wait(t, tt.want)
		if got := recv(c, 50*time.Millisecond); got != nil {
			t.Errorf("%s: relay answered %x (reflection)", tt.name, got)
		}
	}
	// Filling the buffer exactly means possibly truncated: dropped.
	_, _ = c.WriteTo(dgram(to, string(make([]byte, maxDgram-10))), relay)
	if got := recv(c, 100*time.Millisecond); got != nil {
		t.Errorf("full-size datagram relayed")
	}
	// Oversize target datagrams are dropped, not truncated.
	_, _ = c.WriteTo(dgram(apOf(big.LocalAddr()), "hi"), relay)
	b := make([]byte, 100)
	_ = big.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, src, err := big.ReadFromUDPAddrPort(b)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = big.WriteToUDPAddrPort(make([]byte, maxDgram), src)
	d.wait(t, server.ErrTooLarge)
	if got := recv(c, 100*time.Millisecond); got != nil {
		t.Errorf("oversize answer relayed: %d bytes", len(got))
	}
	_, _ = big.WriteToUDPAddrPort(make([]byte, maxDgram-10-22), src)
	if got := recv(c, 5*time.Second); len(got) != maxDgram-22 {
		t.Errorf("answer at the limit: %d bytes", len(got))
	}
}

// Names count toward MaxTargets, failed lookups too.
func TestUDPMaxTargets(t *testing.T) {
	e1, e2 := echoUDP(t, "127.0.0.1:0"), echoUDP(t, "127.0.0.1:0")
	d := &drops{}
	h := &server.AssociateHandler{Filter: server.AllowAll, MaxTargets: 3, Resolver: fakeDNS{"e1.test": "127.0.0.1"}}
	proxy := serve(t, assocServer(h, d))
	_, relay := assoc(t, proxy, "0.0.0.0:0")
	c := udpSock(t)
	name := func(n string, p netip.AddrPort) []byte {
		h, _ := wire.AppendUDPHeader(nil, 0, mustAddr(n+":"+strconv.Itoa(int(p.Port()))))
		return append(h, "x"...)
	}
	p1 := apOf(e1.LocalAddr())
	_, _ = c.WriteTo(name("nx1.test", p1), relay) // 1: failed lookup
	_, _ = c.WriteTo(name("e1.test", p1), relay)  // 2: name
	if got := recv(c, 5*time.Second); got == nil {
		t.Fatal("e1.test not relayed")
	}
	_, _ = c.WriteTo(dgram(p1, "x"), relay) // 3: the IP:port target counts apart from the name
	recv(c, 5*time.Second)
	_, _ = c.WriteTo(dgram(apOf(e2.LocalAddr()), "x"), relay) // 4th: over
	d.wait(t, server.ErrTooManyTargets)
	_, _ = c.WriteTo(name("nx2.test", p1), relay) // over
	if got := recv(c, 100*time.Millisecond); got != nil {
		t.Fatalf("over MaxTargets relayed %x", got)
	}
	_, _ = c.WriteTo(dgram(p1, "again"), relay) // known target
	if got := recv(c, 5*time.Second); !bytes.HasSuffix(got, []byte("again")) {
		t.Fatalf("known target: %q", got)
	}
}

// A name resolving to a denied IP is dropped with the Filter's error.
func TestUDPNameToPrivate(t *testing.T) {
	trap, from := spyUDP(t)
	d := &drops{}
	h := &server.AssociateHandler{Resolver: fakeDNS{"internal.test": "127.0.0.1"}}
	proxy := serve(t, assocServer(h, d))
	_, relay := assoc(t, proxy, "0.0.0.0:0")
	c := udpSock(t)
	hdr, _ := wire.AppendUDPHeader(nil, 0, mustAddr("internal.test:"+strconv.Itoa(int(apOf(trap.LocalAddr()).Port()))))
	_, _ = c.WriteTo(append(hdr, "x"...), relay)
	d.wait(t, server.ErrNotAllowed)
	_, _ = c.WriteTo(dgram(apOf(trap.LocalAddr()), "literal"), relay)
	select {
	case ap := <-from:
		t.Fatalf("denied target got a datagram from %v", ap)
	case <-time.After(200 * time.Millisecond):
	}
}

// Relayed traffic keeps an association alive past IdleTimeout; dropped datagrams do not.
func TestUDPIdle(t *testing.T) {
	t.Run("relayed", func(t *testing.T) {
		e := echoUDP(t, "127.0.0.1:0")
		proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll, IdleTimeout: 300 * time.Millisecond}, nil))
		ctl, relay := assoc(t, proxy, "0.0.0.0:0")
		c := udpSock(t)
		start := time.Now()
		for range 6 {
			_, _ = c.WriteTo(dgram(apOf(e.LocalAddr()), "keep"), relay)
			if recv(c, 5*time.Second) == nil {
				t.Fatal("no echo")
			}
			time.Sleep(100 * time.Millisecond)
		}
		expectEOF(t, ctl)
		if d := time.Since(start); d < 600*time.Millisecond || d > 3*time.Second {
			t.Errorf("ended after %v", d)
		}
	})
	t.Run("dropped", func(t *testing.T) {
		d := &drops{}
		proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll, IdleTimeout: 300 * time.Millisecond}, d))
		ctl, relay := assoc(t, proxy, "127.0.0.1:1") // port 1: every real datagram is from another source
		spray, err := net.DialUDP("udp", nil, relay)
		if err != nil {
			t.Fatal(err)
		}
		defer spray.Close()
		for stop := time.Now().Add(1500 * time.Millisecond); time.Now().Before(stop); time.Sleep(100 * time.Millisecond) {
			_, _ = spray.Write([]byte("junk"))
		}
		_ = ctl.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err = ctl.Read(make([]byte, 1))
		if len(d.list()) == 0 || timedOut(err) {
			t.Fatalf("IdleTimeout 300ms, after 1.5s of dropped datagrams (%d drops): association alive (%v)", len(d.list()), err)
		}
	})
}

// wrappedPC hides *net.UDPConn to force the relay's generic path.
type wrappedPC struct{ net.PacketConn }

// The relay works over sockets that are not *net.UDPConn, with Advertise, and over IPv6.
func TestUDPRelaySockets(t *testing.T) {
	var advertised netip.AddrPort
	wrapped := func(ctx context.Context, network, address string) (net.PacketConn, error) {
		pc, err := net.ListenPacket(network, address)
		return wrappedPC{pc}, err
	}
	generic := &server.AssociateHandler{Filter: server.AllowAll, ListenClient: wrapped, ListenTarget: wrapped,
		Advertise: func(r *server.Request, relay netip.AddrPort) wire.Addr {
			advertised = relay
			return wire.AddrFromAddrPort(relay)
		}}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		if ip == "::1" && !hasIPv6() {
			continue
		}
		t.Run(ip, func(t *testing.T) {
			h, dst := generic, "0.0.0.0:0"
			if ip == "::1" {
				h, dst = &server.AssociateHandler{Filter: server.AllowAll}, "[::]:0"
			}
			e := echoUDP(t, net.JoinHostPort(ip, "0"))
			proxy := serveLn(t, assocServer(h, nil), listen(t, net.JoinHostPort(ip, "0")))
			_, relay := assoc(t, proxy, dst)
			if ip == "::1" && !relay.IP.Equal(net.IPv6loopback) || h == generic && advertised != relay.AddrPort() {
				t.Errorf("relay %v, advertised %v", relay, advertised)
			}
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, _ = c.WriteTo(dgram(apOf(e.LocalAddr()), "relayed"), relay)
			if got := recv(c, 5*time.Second); !bytes.Equal(got, dgram(apOf(e.LocalAddr()), "relayed")) {
				t.Fatalf("%x", got)
			}
		})
	}
}

// A relay-goroutine panic is logged and ends the association, closing the control conn.
func TestUDPRelayPanic(t *testing.T) {
	var lb logBuf
	done := make(chan error, 1)
	panicFilter := func(*server.Request, string, netip.AddrPort) error { panic("filter bug") }
	s := &server.Server{ErrorLog: newLogger(&lb), Handler: &server.AssociateHandler{Filter: panicFilter},
		Trace: &server.ServerTrace{Done: func(_ context.Context, _ *server.Request, _ server.ConnStats, err error) { done <- err }}}
	ctl, relay := assoc(t, serve(t, s), "0.0.0.0:0")
	u := udpSock(t)
	_, _ = u.WriteTo(dgram(netip.MustParseAddrPort("192.0.2.1:53"), "x"), relay)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "panicked") || !strings.Contains(lb.String(), "panic") || !strings.Contains(lb.String(), "filter bug") {
			t.Fatalf("ServeConn: %v; log %q", err, lb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("association alive after a relay panic")
	}
	if _, err := ctl.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("control conn after the relay panic: %v", err)
	}
}
