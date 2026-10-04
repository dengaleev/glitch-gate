package socks0_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// udpProxy serves UDP ASSOCIATE (relay on loopback) and CONNECT, no auth.
type udpProxy struct {
	network string                               // relay network: "udp4" (default) or "udp6"
	bnd     func(relay netip.AddrPort) wire.Addr // BND sent; nil: the relay's address
	nat     bool                                 // answer from another socket than the relay
	rep     wire.Reply
	got     chan wire.Addr      // receives DST, if not nil
	raw     chan []byte         // receives each datagram from the client, if not nil
	assoc   chan *association   // receives each association, if not nil
	resolve func(string) string // maps names in DST.ADDR; nil: "localhost" → 127.0.0.1
}

type association struct {
	control  net.Conn
	relay    *net.UDPConn // receives from the client
	out      *net.UDPConn // sends to the client (relay, or another socket)
	clientMu sync.Mutex
	client   netip.AddrPort
	first    chan struct{} // closed on the first datagram from the client
	ended    chan struct{} // closed when the client closed the control conn
}

func (a *association) send(t testing.TB, b []byte) {
	t.Helper()
	<-a.first
	a.clientMu.Lock()
	to := a.client
	a.clientMu.Unlock()
	if _, err := a.out.WriteToUDPAddrPort(b, to); err != nil {
		t.Error(err)
	}
}

func (p udpProxy) serve(c net.Conn) {
	if _, err := wire.ReadGreeting(c); err != nil {
		return
	}
	c.Write(wire.AppendMethodSelection(nil, wire.MethodNoAuth))
	cmd, dst, err := wire.ReadRequest(c)
	if err != nil {
		return
	}
	if p.got != nil {
		p.got <- dst
	}
	switch {
	case p.rep != 0:
		c.Write(reply(p.rep, "0.0.0.0:0"))
		return
	case cmd == wire.CmdConnect:
		p.connect(c, dst)
		return
	case cmd != wire.CmdUDPAssociate:
		c.Write(reply(wire.ReplyCommandNotSupported, "0.0.0.0:0"))
		return
	}
	network, loop := p.network, "127.0.0.1:0"
	if network == "udp6" {
		loop = "[::1]:0"
	} else {
		network = "udp4"
	}
	relay, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(loop)))
	if err != nil {
		return
	}
	defer relay.Close()
	a := &association{control: c, relay: relay, out: relay, first: make(chan struct{}), ended: make(chan struct{})}
	if p.nat {
		if a.out, err = net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(loop))); err != nil {
			return
		}
		defer a.out.Close()
	}
	up, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(loop)))
	if err != nil {
		return
	}
	defer up.Close()
	bnd := wire.AddrFromAddrPort(relay.LocalAddr().(*net.UDPAddr).AddrPort())
	if p.bnd != nil {
		bnd = p.bnd(relay.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	b, _ := wire.AppendReply(nil, wire.ReplySucceeded, bnd)
	c.Write(b)
	if p.assoc != nil {
		p.assoc <- a
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { p.fromClient(a, up) })
	wg.Go(func() { p.toClient(a, up) })
	if _, err := io.Copy(io.Discard, c); err == nil {
		close(a.ended)
	}
	relay.Close()
	up.Close()
	a.out.Close()
}

func (p udpProxy) fromClient(a *association, up *net.UDPConn) {
	buf := make([]byte, 64<<10)
	var once sync.Once
	for {
		n, from, err := a.relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		a.clientMu.Lock()
		a.client = from
		a.clientMu.Unlock()
		once.Do(func() { close(a.first) })
		if p.raw != nil {
			p.raw <- append([]byte(nil), buf[:n]...)
		}
		frag, dst, hn, err := wire.ParseUDPHeader(buf[:n])
		if err != nil || frag != 0 {
			continue
		}
		to, err := p.lookup(dst)
		if err != nil {
			continue
		}
		up.WriteToUDPAddrPort(buf[hn:n], to)
	}
}

func (p udpProxy) toClient(a *association, up *net.UDPConn) {
	buf, hbuf := make([]byte, 64<<10), make([]byte, 0, wire.MaxUDPHeaderLen)
	for {
		n, from, err := up.ReadFromUDPAddrPort(buf[wire.MaxUDPHeaderLen:])
		if err != nil {
			return
		}
		hdr, _ := wire.AppendUDPHeader(hbuf[:0], 0, wire.AddrFromAddrPort(from))
		d := buf[wire.MaxUDPHeaderLen-len(hdr) : wire.MaxUDPHeaderLen+n]
		copy(d, hdr)
		a.clientMu.Lock()
		to := a.client
		a.clientMu.Unlock()
		a.out.WriteToUDPAddrPort(d, to)
	}
}

func (p udpProxy) lookup(a wire.Addr) (netip.AddrPort, error) {
	if !a.IsName() {
		return netip.AddrPortFrom(a.IP(), a.Port()), nil
	}
	host := "127.0.0.1"
	if p.resolve != nil {
		host = p.resolve(a.Name())
	}
	ip, err := netip.ParseAddr(host)
	return netip.AddrPortFrom(ip, a.Port()), err
}

func (p udpProxy) connect(c net.Conn, dst wire.Addr) {
	to, err := p.lookup(dst)
	if err != nil {
		return
	}
	t, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(to))
	if err != nil {
		c.Write(reply(wire.ReplyConnectionRefused, "0.0.0.0:0"))
		return
	}
	defer t.Close()
	c.Write(reply(wire.ReplySucceeded, t.LocalAddr().String()))
	go func() { io.Copy(t, c); t.CloseWrite() }()
	io.Copy(c, t)
}

func udpServe(t testing.TB, network string, handle func(b []byte) []byte) netip.AddrPort {
	t.Helper()
	loop := "127.0.0.1:0"
	if network == "udp6" {
		loop = "[::1]:0"
	}
	c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(loop)))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if resp := handle(buf[:n]); resp != nil {
				c.WriteToUDPAddrPort(resp, from)
			}
		}
	})
	t.Cleanup(func() { c.Close(); wg.Wait() })
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func echo(b []byte) []byte { return b }

// dnsAnswer answers A with ip, others with no records; tc sets TC, no answers.
func dnsAnswer(ip netip.Addr, tc bool) func([]byte) []byte {
	return func(q []byte) []byte {
		if len(q) < 12 {
			return nil
		}
		end := 12
		for end < len(q) && q[end] != 0 {
			end += 1 + int(q[end])
		}
		end += 5 // root label, QTYPE, QCLASS
		if end > len(q) {
			return nil
		}
		r := append([]byte(nil), q[:end]...)
		r[2] |= 0x80 // QR
		r[3] = 0x80  // RA, NOERROR
		binary.BigEndian.PutUint16(r[6:], 0)
		binary.BigEndian.PutUint16(r[8:], 0)
		binary.BigEndian.PutUint16(r[10:], 0)
		if tc {
			r[2] |= 0x02
			return r
		}
		if binary.BigEndian.Uint16(q[end-4:]) == 1 { // A
			binary.BigEndian.PutUint16(r[6:], 1)
			r = append(r, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			r = append(r, ip.AsSlice()...)
		}
		return r
	}
}

func dnsTCP(t testing.TB, answer func([]byte) []byte) string {
	return listen(t, func(c net.Conn) {
		for {
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			r := answer(q)
			c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
		}
	})
}

// dialCtx adapts a DialContext to a func without ctx (beevik/ntp's Dialer).
func dialCtx(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network string) func(string, string) (net.Conn, error) {
	return func(_, remote string) (net.Conn, error) { return dial(ctx, network, remote) }
}
