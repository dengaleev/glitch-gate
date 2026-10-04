package socks0

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Listen makes a BIND request and returns once the proxy listens. address is
// not local but the expected peer, sent as DST ("" if unknown; SOCKS4 needs
// the peer's IP). ctx bounds the first reply only. Errors are
// *net.OpError{Op: "socks bind"}. ModeEarly runs as ModePipelined.
func (d *Dialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var target wire.Addr
	var err error
	switch {
	case network != "tcp" && network != "tcp4" && network != "tcp6":
		err = net.UnknownNetworkError(network)
	case address == "":
		target = unknownDST
	default:
		target, err = d.parseTarget(network, address)
	}
	c := new(Conn)
	_, err = d.newConn(&ctx, c, opBind, network, wire.CmdBind, target, err)
	if err != nil {
		return nil, err
	}
	conn, tr, err := d.connect(ctx, c)
	if err != nil {
		return nil, err
	}
	l := &Listener{c: c, conn: conn, bound: c.h.bound, tr: tr}
	a, err := d.substitute(ctx, l.bound, conn, false, false)
	if err != nil {
		a, _ = d.substitute(ctx, l.bound, conn, false, true) // keep the proxy's name
	}
	l.addr = netAddr(a, false)
	return l, nil
}

func netAddr(a wire.Addr, udp bool) net.Addr {
	switch ap := netip.AddrPortFrom(a.IP(), a.Port()); {
	case a.IsName():
		return a
	case udp:
		return net.UDPAddrFromAddrPort(ap)
	default:
		return net.TCPAddrFromAddrPort(ap)
	}
}

// Listener is a BIND in progress; it accepts exactly one connection.
type Listener struct {
	c     *Conn // the handshake, then the accepted conn
	conn  net.Conn
	addr  net.Addr
	bound wire.Addr
	tr    tracer

	mu     sync.Mutex
	state  listenerState
	closed bool // before Accept returned a conn
}

type listenerState uint8

const (
	listenerListening listenerState = iota
	listenerAccepting
	listenerDone
)

// Accept waits for the second reply and returns a *Conn to the peer. Later and
// concurrent calls fail matching net.ErrClosed. Errors are at StageAccept.
func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.state != listenerListening {
		l.mu.Unlock()
		return nil, l.c.opError(&HandshakeError{StageAccept, net.ErrClosed})
	}
	l.state = listenerAccepting
	l.mu.Unlock()

	peer, err := l.c.h.readSecondReply(l.conn)

	l.mu.Lock()
	l.state = listenerDone
	if l.closed {
		err = net.ErrClosed
	}
	l.mu.Unlock()
	if err != nil {
		l.conn.Close()
		err = l.c.opError(&HandshakeError{StageAccept, err})
		l.tr.accepted(peer, err)
		return nil, err
	}
	l.tr.accepted(peer, nil)
	l.conn.SetDeadline(time.Time{})
	c := l.c
	c.conn, c.laddr, c.raddr, c.bound = l.conn, l.addr, netAddr(peer, false), peer
	c.claimed, c.written, c.done, c.traceSet = true, true, true, true
	c.readReady.Store(true)
	c.writeReady.Store(true)
	return c, nil
}

// Addr is where the peer must connect: BND, substituted if unspecified.
func (l *Listener) Addr() net.Addr { return l.addr }

// BoundAddr is BND of the first reply as sent.
func (l *Listener) BoundAddr() wire.Addr { return l.bound }

// SetDeadline bounds Accept.
func (l *Listener) SetDeadline(t time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == listenerDone {
		return l.c.opError(&HandshakeError{StageAccept, net.ErrClosed})
	}
	return l.conn.SetReadDeadline(t)
}

// Close fails a pending Accept with net.ErrClosed; after Accept it does nothing.
func (l *Listener) Close() error {
	l.mu.Lock()
	switch {
	case l.closed:
		l.mu.Unlock()
		return l.c.opError(&HandshakeError{StageAccept, net.ErrClosed})
	case l.state == listenerDone:
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.state == listenerListening {
		l.state = listenerDone
	}
	l.mu.Unlock()
	return l.conn.Close()
}
