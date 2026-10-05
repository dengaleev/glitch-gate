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
	conn, err := d.connect(ctx, c)
	if err != nil {
		return nil, err
	}
	l := &Listener{c: c, conn: conn}
	proxy := d.proxyHost()
	a, err := d.substitute(ctx, c.h.bound, conn, proxy, false, false)
	if err != nil {
		a, _ = d.substitute(ctx, c.h.bound, conn, proxy, false, true) // keep the proxy's name
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
	c    *Conn // the handshake (c.h.bound: the first BND), then the accepted conn; c.conn under mu
	conn net.Conn
	addr net.Addr

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
		defer l.mu.Unlock()
		return nil, l.closedErrLocked()
	}
	l.state = listenerAccepting
	l.mu.Unlock()

	c := l.c
	peer, err := c.h.readSecondReply(l.conn)

	l.mu.Lock()
	l.state = listenerDone
	if l.closed {
		err = net.ErrClosed
	}
	if err == nil { // c.conn names the proxy in errors of concurrent calls
		c.conn, c.laddr, c.raddr, c.phase = l.conn, l.addr, netAddr(peer, false), phaseSent
	}
	l.mu.Unlock()
	if err != nil {
		l.conn.Close()
		err = c.opError(&HandshakeError{StageAccept, err})
		c.trace.accepted(peer, err)
		return nil, err
	}
	c.trace.accepted(peer, nil)
	l.conn.SetDeadline(time.Time{})
	c.establishLocked(peer)
	return c, nil
}

func (l *Listener) closedErrLocked() error {
	return l.c.opError(&HandshakeError{StageAccept, net.ErrClosed})
}

// Addr is where the peer must connect: BND, substituted if unspecified.
func (l *Listener) Addr() net.Addr { return l.addr }

// BoundAddr is BND of the first reply as sent.
func (l *Listener) BoundAddr() wire.Addr { return l.c.h.bound }

// SetDeadline bounds Accept.
func (l *Listener) SetDeadline(t time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == listenerDone {
		return l.closedErrLocked()
	}
	return l.conn.SetReadDeadline(t)
}

// Close fails a pending Accept with net.ErrClosed; after Accept it does nothing.
func (l *Listener) Close() error {
	l.mu.Lock()
	switch {
	case l.closed:
		defer l.mu.Unlock()
		return l.closedErrLocked()
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
