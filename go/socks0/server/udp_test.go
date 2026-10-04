package server_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type drops struct {
	mu  sync.Mutex
	got []error
}

func (d *drops) trace() *server.ServerTrace {
	return &server.ServerTrace{Dropped: func(_ context.Context, _ netip.AddrPort, err error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.got = append(d.got, err)
	}}
}

func (d *drops) wait(t testing.TB, target error) {
	t.Helper()
	waitFor(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, err := range d.got {
			if errors.Is(err, target) {
				return true
			}
			if _, ok := target.(*wire.ProtocolError); ok {
				if _, ok := errors.AsType[*wire.ProtocolError](err); ok {
					return true
				}
			}
		}
		return false
	})
}

func assoc(t testing.TB, proxy, dst string) (*net.TCPConn, *net.UDPAddr) {
	t.Helper()
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, dst)))
	expect(t, c, []byte{5, 0})
	rep, relay := readReply(t, c, wire.CmdUDPAssociate)
	if rep != 0 {
		t.Fatalf("ASSOCIATE: %v", rep)
	}
	return c, net.UDPAddrFromAddrPort(netip.AddrPortFrom(relay.IP(), relay.Port()))
}

func udpSock(t testing.TB) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func dgram(to netip.AddrPort, payload string) []byte {
	h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(to))
	return append(h, payload...)
}

func apOf(a net.Addr) netip.AddrPort { return a.(*net.UDPAddr).AddrPort() }

// recv returns nil on timeout.
func recv(c *net.UDPConn, d time.Duration) []byte {
	_ = c.SetReadDeadline(time.Now().Add(d))
	b := make([]byte, 65536)
	n, err := c.Read(b)
	if err != nil {
		return nil
	}
	return b[:n]
}

func assocServer(h *server.AssociateHandler, d *drops) *server.Server {
	s := open()
	s.Handler = h
	if d != nil {
		s.Trace = d.trace()
	}
	return s
}

func TestUDPSourceLock(t *testing.T) {
	e := echoUDP(t, "127.0.0.1:0")
	d := &drops{}
	proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll}, d))
	_, relay := assoc(t, proxy, "0.0.0.0:0")
	a, b := udpSock(t), udpSock(t)
	_, _ = a.WriteTo(dgram(apOf(e.LocalAddr()), "from a"), relay)
	if got := recv(a, 5*time.Second); !bytes.HasSuffix(got, []byte("from a")) {
		t.Fatalf("a: %q", got)
	}
	_, _ = b.WriteTo(dgram(apOf(e.LocalAddr()), "from b"), relay)
	d.wait(t, server.ErrWrongSource)
	if got := recv(b, 100*time.Millisecond); got != nil {
		t.Fatalf("b got %q", got)
	}

	// DST with the client's own IP locks the port from the start.
	a, b = udpSock(t), udpSock(t)
	_, relay = assoc(t, proxy, a.LocalAddr().String())
	_, _ = b.WriteTo(dgram(apOf(e.LocalAddr()), "b first"), relay)
	if got := recv(b, 200*time.Millisecond); got != nil {
		t.Fatalf("b got %q", got)
	}
	_, _ = a.WriteTo(dgram(apOf(e.LocalAddr()), "a"), relay)
	if got := recv(a, 5*time.Second); !bytes.HasSuffix(got, []byte("a")) {
		t.Fatalf("a: %q", got)
	}

	// DST with another IP is ignored: the relay cannot be pointed at a victim.
	a = udpSock(t)
	_, relay = assoc(t, proxy, "192.0.2.1:"+strconv.Itoa(int(apOf(a.LocalAddr()).Port())))
	_, _ = a.WriteTo(dgram(apOf(e.LocalAddr()), "a2"), relay)
	if got := recv(a, 5*time.Second); !bytes.HasSuffix(got, []byte("a2")) {
		t.Fatalf("a: %q", got)
	}
}

func spyUDP(t testing.TB) (*net.UDPConn, <-chan netip.AddrPort) {
	pc := udpSock(t)
	from := make(chan netip.AddrPort, 1)
	go func() {
		b := make([]byte, 100)
		_, ap, err := pc.ReadFromUDPAddrPort(b)
		if err == nil {
			from <- ap
		}
	}()
	return pc, from
}

func TestUDPFiltering(t *testing.T) {
	for _, tt := range []struct {
		mode               server.Filtering
		samePort, samePeer bool // reaches the client from: the target's other port; another socket on its IP
	}{
		{server.AddressAndPortDependent, false, false},
		{server.AddressDependent, true, true},
		{server.EndpointIndependent, true, true},
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
			// The contacted target is always delivered.
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

// S6: names count toward MaxTargets, failed lookups too.
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

func TestUDPIdle(t *testing.T) {
	e := echoUDP(t, "127.0.0.1:0")
	proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll, IdleTimeout: 300 * time.Millisecond}, nil))
	ctl, relay := assoc(t, proxy, "0.0.0.0:0")
	c := udpSock(t)
	start := time.Now()
	for range 6 { // traffic keeps it alive past the timeout
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
}
