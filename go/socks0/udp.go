package socks0

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/internal/neterr"
	"github.com/dengaleev/glitch-gate/go/socks0/internal/sockopt"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	errRelayBoth   = errors.New("socks0: both RelayDial and RelayListen are set")
	errDSTPort     = errors.New("socks0: a DST port needs RelayDial or RelayListen to bind it")
	errNoRelayConn = errors.New("socks0: RelayDial or RelayListen returned no conn and no error")
	errLocalPort   = errors.New("socks0: AssociateLocalPort needs an unknown DST and no RelayDial")
	errNoLocalPort = errors.New("socks0: the relay socket has no UDP port")
	unknownDST     = addrPort(netip.IPv4Unspecified(), 0)
)

// ListenPacket is ListenUDP returning a net.PacketConn.
func (d *Dialer) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	c, err := d.ListenUDP(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListenUDP opens an unconnected UDP association. A "udp4"/"udp6" suffix
// restricts WriteTo's IP targets. address is not local but sent as DST
// (overriding AssociateAddr; ""/":0" is unknown); a non-zero port needs
// RelayDial or RelayListen. ctx bounds the setup only. Errors are
// *net.OpError{Op: "socks udp associate"}. ModeEarly runs as ModePipelined.
func (d *Dialer) ListenUDP(ctx context.Context, network, address string) (*UDPConn, error) {
	var err error
	switch network {
	case "udp", "udp4", "udp6":
	default:
		err = net.UnknownNetworkError(network)
	}
	return d.associate(ctx, network, wire.Addr{}, err, address)
}

func (d *Dialer) parseDST(address string) (wire.Addr, error) {
	if address == "" || address == ":0" {
		return unknownDST, nil
	}
	a, err := wire.ParseAddr(address)
	switch {
	case err != nil:
		return a, err
	case a.Port() == 0 && a.IP().IsUnspecified():
		return unknownDST, nil
	case a.Port() != 0 && d.RelayDial == nil && d.RelayListen == nil:
		return a, errDSTPort
	}
	return a, nil
}

func (d *Dialer) associateDST(dst string) (wire.Addr, error) {
	req, err := d.parseDST(dst)
	switch {
	case err != nil:
	case d.RelayDial != nil && d.RelayListen != nil:
		err = errRelayBoth
	case d.AssociateLocalPort && (d.RelayDial != nil || req != unknownDST):
		err = errLocalPort
	}
	return req, err
}

func (d *Dialer) associate(ctx context.Context, network string, target wire.Addr, err error, dst string) (*UDPConn, error) {
	var req wire.Addr
	if d != nil && err == nil {
		req, err = d.associateDST(dst)
	}
	connected := target.IsValid()
	if !connected {
		target = req
	}
	c := &Conn{doneAfterRelay: true}
	resolved, err := d.newConn(&ctx, c, opAssociate, network, wire.CmdUDPAssociate, target, err)
	if err != nil {
		return nil, err
	}
	if !connected {
		resolved = wire.Addr{}
	}
	pre, err := d.setRequestDST(ctx, c, network, req, connected)
	if err != nil {
		return nil, err
	}
	conn, err := d.connect(ctx, c)
	if err != nil {
		if pre != nil {
			pre.Close()
		}
		return nil, err
	}
	u, err := d.openRelay(ctx, c, conn, pre)
	if err != nil {
		return nil, err
	}
	u.bound, u.tr, u.network = c.h.bound, c.trace, network
	return u.start(conn, resolved), nil
}

func (d *Dialer) setRequestDST(ctx context.Context, c *Conn, network string, req wire.Addr, connected bool) (pre net.PacketConn, _ error) {
	target := c.h.target
	if d.AssociateLocalPort {
		var err error
		if pre, err = d.prebind(ctx, network); err != nil {
			return nil, c.opError(&HandshakeError{StageRelayDial, ctxErr(ctx, err)})
		}
		req = addrPort(netip.IPv4Unspecified(), uint16(pre.LocalAddr().(*net.UDPAddr).Port))
		if !connected {
			target = req
		}
	}
	if connected || pre != nil {
		c.h.setTarget(req) // valid: parsed, or built
		c.h.target = target
	}
	return pre, nil
}

// openRelay ends the handshake: HandshakeDone runs after the relay dial.
func (d *Dialer) openRelay(ctx context.Context, c *Conn, control net.Conn, pre net.PacketConn) (*udpState, error) {
	rctx, cancel := c.handshakeCtx(ctx)
	s, err := d.relay(rctx, control, c.h.bound, c.trace, pre)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		control.Close()
		err = c.opError(&HandshakeError{StageRelayDial, ctxErr(ctx, err)})
		s = nil
	}
	c.trace.handshakeDone(err)
	return s, err
}

func (d *Dialer) prebind(ctx context.Context, network string) (net.PacketConn, error) {
	listen := d.RelayListen
	if listen == nil {
		listen = sockopt.ListenNoBroadcast
	}
	pc, err := listen(ctx, network, ":0")
	if err = dialErr(pc, err, errNoRelayConn); err != nil {
		return nil, err
	}
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); !ok || ua.Port == 0 {
		pc.Close()
		return nil, errNoLocalPort
	}
	return pc, nil
}

func (d *Dialer) relay(ctx context.Context, control net.Conn, bound wire.Addr, tr *ClientTrace, pre net.PacketConn) (*udpState, error) {
	ra, proxyIP, err := d.relayAddr(ctx, control, bound)
	if err != nil {
		if pre != nil {
			pre.Close()
		}
		return nil, err
	}
	network := udpNetwork(ra.IP())
	tr.relayDialStart(network, ra.String())
	s := new(udpState)
	if d.RelayListen == nil && pre == nil {
		s.relay, err = d.dialRelay(ctx, network, ra, proxyIP)
	} else {
		ra, err = d.listenRelay(ctx, s, network, ra, proxyIP, pre)
	}
	tr.relayDialDone(network, ra.String(), err)
	return s, err
}

// relayAddr applies the relay address policy (security: hostile BND).
func (d *Dialer) relayAddr(ctx context.Context, control net.Conn, bound wire.Addr) (ra wire.Addr, proxyIP netip.Addr, err error) {
	proxy := d.proxyHost()
	ra, err = d.substitute(ctx, bound, control, proxy, d.RelayUseProxyHost, d.RelayDial != nil && d.ProxyDial != nil)
	if proxyIP = proxy.ip; !proxyIP.IsValid() {
		proxyIP = remoteIP(control)
	}
	if err == nil && ra.IP().IsValid() {
		err = checkRelay(ra.IP(), proxyIP)
	}
	return ra, proxyIP, err
}

func udpNetwork(ip netip.Addr) string {
	switch {
	case ip.Is4():
		return "udp4"
	case ip.Is6():
		return "udp6"
	}
	return "udp"
}

func (d *Dialer) dialRelay(ctx context.Context, network string, ra wire.Addr, proxyIP netip.Addr) (net.Conn, error) {
	dial := d.RelayDial
	if dial == nil {
		dial = (&net.Dialer{ControlContext: relayControl(proxyIP)}).DialContext
	}
	conn, err := dial(ctx, network, ra.String())
	return conn, dialErr(conn, err, errNoRelayConn)
}

func (d *Dialer) listenRelay(ctx context.Context, s *udpState, network string, ra wire.Addr, proxyIP netip.Addr, pre net.PacketConn) (wire.Addr, error) {
	var err error
	if ra.IsName() {
		if ra, err = resolveFirst(ctx, ra, false); err == nil {
			err = checkRelay(ra.IP(), proxyIP)
		}
	}
	switch {
	case err != nil:
	case pre != nil:
		s.pc = pre
	default:
		s.pc, err = d.RelayListen(ctx, network, ":0")
	}
	if err = dialErr(s.pc, err, errNoRelayConn); err != nil && pre != nil {
		pre.Close()
	}
	s.relayAP = netip.AddrPortFrom(ra.IP(), ra.Port())
	return ra, err
}

// substitute replaces an unspecified (or, if force, any) BND IP with the
// proxy's host: ProxyAddr's IP; else, without ProxyDial, the control peer's
// IP; else ProxyAddr's name (resolved unless keepName).
func (d *Dialer) substitute(ctx context.Context, bound wire.Addr, control net.Conn, proxy proxyHost, force, keepName bool) (wire.Addr, error) {
	ip := bound.IP()
	switch {
	case !force && !ip.IsUnspecified():
		return bound, nil
	case proxy.err != nil:
		return wire.Addr{}, proxy.err
	case proxy.ip.IsValid():
		return addrPort(proxy.ip, bound.Port()), nil
	}
	peer := remoteIP(control)
	if d.ProxyDial == nil && peer.IsValid() && (!ip.Is4() || peer.Is4()) {
		return addrPort(peer, bound.Port()), nil
	}
	name, err := nameAddr(proxy.name, bound.Port())
	if err != nil || keepName {
		return name, err
	}
	return d.resolveProxyHost(ctx, name, ip, peer)
}

func (d *Dialer) resolveProxyHost(ctx context.Context, name wire.Addr, boundIP, peer netip.Addr) (wire.Addr, error) {
	if d.ProxyDial == nil && peer.IsValid() {
		// An IPv6 control conn and an IPv4 BND: the proxy's IPv4, if any.
		if a, err := resolveFirst(ctx, name, true); err == nil && a.IP().Is4() {
			return a, nil
		}
		return addrPort(peer, name.Port()), nil
	}
	ips, err := lookupIPs(ctx, name.Name())
	if err != nil {
		return wire.Addr{}, err
	}
	return addrPort(pickRelayIP(ips, peer, boundIP), name.Port()), nil
}

// lookupIPs resolves name with net.DefaultResolver, unmapping the IPs.
func lookupIPs(ctx context.Context, name string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	return ips, err
}

func remoteIP(control net.Conn) netip.Addr {
	if ta, ok := control.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// pickRelayIP prefers the control peer, but for an IPv4 BND only if IPv4:
// 0.0.0.0 is an IPv4-only socket, while :: usually takes both families.
func pickRelayIP(ips []netip.Addr, peer, bound netip.Addr) netip.Addr {
	if (!bound.Is4() || peer.Is4()) && slices.Contains(ips, peer) {
		return peer
	}
	for _, ip := range ips {
		if ip.Is4() == bound.Is4() {
			return ip
		}
	}
	return ips[0]
}

func resolveFirst(ctx context.Context, a wire.Addr, want4 bool) (wire.Addr, error) {
	ips, err := lookupIPs(ctx, a.Name())
	if err != nil {
		return wire.Addr{}, err
	}
	ip := ips[0]
	if i := slices.IndexFunc(ips, netip.Addr.Is4); want4 && i >= 0 {
		ip = ips[i]
	}
	return addrPort(ip, a.Port()), nil
}

// UDPConn is a UDP association (TCP control conn + UDP relay socket); a
// net.PacketConn and net.Conn, safe for concurrent use.
// Reads return one datagram, truncated to b without error. Malformed, FRAG ≠
// 0 and (connected, IP target) wrong-source datagrams are dropped (see
// ClientTrace.DroppedDatagram). Oversized writes match syscall.EMSGSIZE.
// Security: a relay address (BND, substituted by the proxy's host if
// unspecified or RelayUseProxyHost) that is multicast, broadcast, unspecified
// or more local than the proxy's IP fails at StageRelayDial, matching
// ErrNotAllowed; the default relay dial clears SO_BROADCAST. A custom
// RelayDial gets a BND name unchecked.
// Once the proxy closes the control conn, I/O fails matching
// ErrAssociationClosed and Done is closed. One goroutine per UDPConn; Close
// stops it, as does the GC for an unreachable UDPConn. I/O errors are
// *net.OpError{Net: "udp"}.
type UDPConn struct {
	s       *udpState
	cleanup runtime.Cleanup
}

// udpState is the association; the watcher holds only it, so that an
// unreachable UDPConn can be cleaned up.
type udpState struct {
	control   net.Conn       // nil: dead, nothing open (NewUDPConn without both conns)
	relay     net.Conn       // connected relay, or nil
	pc        net.PacketConn // unconnected relay, or nil
	sock      relaySocket    // relay or pc
	upc       *net.UDPConn   // pc, if it is one: no allocation per datagram
	relayAP   netip.AddrPort // pc's destination; answers come from its IP
	relayAddr net.Addr
	laddr     net.Addr
	target    wire.Addr // zero if unconnected
	raddr     net.Addr  // target as a *net.UDPAddr or wire.Addr; nil if unconnected
	network   string    // "udp4", "udp6": the IP targets allowed
	bound     wire.Addr
	maxLen    int // of a datagram to the relay
	tr        *ClientTrace

	rmu  sync.Mutex
	rbuf []byte
	wmu  sync.Mutex
	wbuf []byte

	closed    atomic.Bool
	mu        sync.Mutex
	err       error         // why the association ended
	done      chan struct{} // closed by the watcher when it exits
	relayOnce sync.Once
}

// relaySocket is what net.Conn and net.PacketConn share.
type relaySocket interface {
	Close() error
	LocalAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

var errNoUDPConn = &HandshakeError{StageConfig, errNoConn}

// NewUDPConn makes a UDPConn from a caller's association (see Request):
// control with nothing read past the reply, relay keeping datagram
// boundaries; a zero target is unconnected. No trace hooks, zero BoundAddr.
// If either conn is nil the other is closed and the UDPConn is dead, with
// errors at StageConfig.
func NewUDPConn(control, relay net.Conn, target wire.Addr) *UDPConn {
	s := &udpState{network: "udp"}
	if control == nil || relay == nil {
		for _, c := range [...]net.Conn{control, relay} {
			if c != nil {
				c.Close()
			}
		}
		s.err = errNoUDPConn
		return s.start(nil, target)
	}
	s.relay = relay
	return s.start(control, target)
}

func (s *udpState) start(control net.Conn, target wire.Addr) *UDPConn {
	s.control, s.target, s.done = control, target, make(chan struct{})
	if target.IsValid() {
		s.raddr = netAddr(target, true)
	}
	s.maxLen = 65535 - 8 - 20
	switch {
	case s.dead():
		close(s.done)
		return &UDPConn{s: s}
	case s.relay != nil:
		s.sock, s.relayAddr = s.relay, s.relay.RemoteAddr()
		if ua, ok := s.relayAddr.(*net.UDPAddr); ok && ua.AddrPort().Addr().Unmap().Is6() {
			s.maxLen = 65535 - 8
		}
	default: // relayAP is from a wire.Addr: unmapped
		s.sock, s.relayAddr = s.pc, net.UDPAddrFromAddrPort(s.relayAP)
		s.upc, _ = s.pc.(*net.UDPConn)
		if s.relayAP.Addr().Is6() {
			s.maxLen = 65535 - 8
		}
	}
	s.laddr = s.sock.LocalAddr()
	go s.watch()
	c := &UDPConn{s: s}
	// In a goroutine: close waits for the watcher, and cleanups must not
	// block.
	c.cleanup = runtime.AddCleanup(c, func(s *udpState) { go s.close() }, s)
	return c
}

func (s *udpState) watch() {
	var buf [256]byte
	var err error
	for err == nil {
		_, err = s.control.Read(buf[:])
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = fmt.Errorf("%w: %w", ErrAssociationClosed, err)
	}
	s.mu.Unlock()
	s.closeRelay()
	close(s.done)
}

func (s *udpState) closeRelay() {
	s.relayOnce.Do(func() { s.sock.Close() })
}

func (s *udpState) dead() bool { return s.control == nil }

const closeWait = time.Second

func (s *udpState) close() error {
	if s.closed.Swap(true) {
		return s.newErr("close", nil, net.ErrClosed)
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = net.ErrClosed
	}
	s.mu.Unlock()
	if s.dead() {
		return nil
	}
	s.control.SetReadDeadline(aLongTimeAgo)
	s.control.Close()
	s.closeRelay()
	t := time.NewTimer(closeWait)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
	}
	return nil
}

// Close closes both conns and waits up to a second for the watcher; later
// calls match net.ErrClosed.
func (c *UDPConn) Close() error {
	c.cleanup.Stop()
	return c.s.close()
}

// Done is closed when the association ends, by the proxy or Close.
func (c *UDPConn) Done() <-chan struct{} { return c.s.done }

// Err is nil while the association lives, then matches ErrAssociationClosed
// (proxy ended it) or net.ErrClosed.
func (c *UDPConn) Err() error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	return c.s.err
}

// ReadFrom's addr is a *net.UDPAddr, or a wire.Addr for a name.
func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, from, err := c.s.readFrom(b)
	runtime.KeepAlive(c)
	if err != nil {
		return 0, nil, err
	}
	return n, netAddr(from, true), nil
}

// ReadFromAddr is ReadFrom without allocation (except a name's string).
func (c *UDPConn) ReadFromAddr(b []byte) (n int, addr wire.Addr, err error) {
	n, addr, err = c.s.readFrom(b)
	runtime.KeepAlive(c)
	return n, addr, err
}

func (c *UDPConn) Read(b []byte) (int, error) {
	n, _, err := c.s.readFrom(b)
	runtime.KeepAlive(c)
	return n, err
}

// WriteTo takes a *net.UDPAddr, wire.Addr or *wire.Addr (names go to the
// proxy unresolved); a connected UDPConn fails with net.ErrWriteToConnected.
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	defer runtime.KeepAlive(c)
	s := c.s
	var to wire.Addr
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a != nil {
			to = wire.AddrFromAddrPort(a.AddrPort())
		}
	case wire.Addr:
		to = a
	case *wire.Addr:
		if a == nil {
			addr = nil // its String would panic in the error's
		} else {
			to = *a
		}
	}
	if s.target.IsValid() {
		return 0, s.newErr("write", addr, net.ErrWriteToConnected)
	}
	return s.writeTo(b, to, addr)
}

// WriteToAddr is WriteTo without allocation.
func (c *UDPConn) WriteToAddr(b []byte, addr wire.Addr) (int, error) {
	defer runtime.KeepAlive(c)
	if c.s.target.IsValid() {
		return 0, c.s.newErr("write", addr, net.ErrWriteToConnected)
	}
	return c.s.writeTo(b, addr, nil)
}

// Write on an unconnected UDPConn fails with syscall.EDESTADDRREQ.
func (c *UDPConn) Write(b []byte) (int, error) {
	defer runtime.KeepAlive(c)
	if !c.s.target.IsValid() {
		return 0, c.s.newErr("write", nil, errDestAddrReq)
	}
	return c.s.writeTo(b, c.s.target, c.s.raddr)
}

func (c *UDPConn) LocalAddr() net.Addr { return c.s.laddr }

// RemoteAddr is the target of a connected UDPConn, else nil.
func (c *UDPConn) RemoteAddr() net.Addr { return c.s.raddr }

// RelayAddr is BND after substitution.
func (c *UDPConn) RelayAddr() net.Addr { return c.s.relayAddr }

// BoundAddr is BND as the proxy sent it.
func (c *UDPConn) BoundAddr() wire.Addr { return c.s.bound }

func (c *UDPConn) SetDeadline(t time.Time) error { return c.s.deadline(t, true, true) }

func (c *UDPConn) SetReadDeadline(t time.Time) error { return c.s.deadline(t, true, false) }

func (c *UDPConn) SetWriteDeadline(t time.Time) error { return c.s.deadline(t, false, true) }

// SyscallConn returns the relay socket's raw conn, or an error matching
// errors.ErrUnsupported.
func (c *UDPConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.s.sock.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, c.s.newErr("raw-conn", nil, errors.ErrUnsupported)
}

func (s *udpState) deadline(t time.Time, read, write bool) error {
	switch {
	case s.dead():
		return s.newErr("set", nil, errNoUDPConn)
	case read && write:
		return s.sock.SetDeadline(t)
	case read:
		return s.sock.SetReadDeadline(t)
	}
	return s.sock.SetWriteDeadline(t)
}

const maxRelayDatagram = 65535

func (s *udpState) readFrom(b []byte) (int, wire.Addr, error) {
	if s.dead() {
		return 0, wire.Addr{}, s.newErr("read", nil, errNoUDPConn)
	}
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if need := min(len(b)+wire.MaxUDPHeaderLen, maxRelayDatagram); cap(s.rbuf) < need {
		s.rbuf = make([]byte, need)
	}
	buf := s.rbuf[:cap(s.rbuf)]
	for {
		n, err := s.readRelay(buf)
		if err != nil {
			return 0, wire.Addr{}, s.ioErr("read", s.raddr, err)
		}
		if n < 0 {
			continue
		}
		frag, from, hn, err := wire.ParseUDPHeader(buf[:n])
		switch {
		case err != nil:
			s.drop(wire.Addr{}, err)
		case frag != 0:
			s.drop(from, ErrFragment)
		case s.target.IP().IsValid() && from != s.target: // an IP target only
			s.drop(from, ErrWrongSource)
		default:
			return copy(b, buf[hn:n]), from, nil
		}
	}
}

// readRelay returns n < 0 for a dropped datagram.
func (s *udpState) readRelay(buf []byte) (int, error) {
	if s.relay != nil {
		return s.relay.Read(buf)
	}
	var from netip.AddrPort
	var n int
	var err error
	if s.upc != nil {
		n, from, err = s.upc.ReadFromUDPAddrPort(buf)
	} else {
		var a net.Addr
		n, a, err = s.pc.ReadFrom(buf)
		ua, ok := a.(*net.UDPAddr)
		if !ok {
			return n, err
		}
		from = ua.AddrPort()
	}
	if err == nil && from.Addr().Unmap() != s.relayAP.Addr() {
		s.drop(wire.AddrFromAddrPort(from), ErrWrongSource)
		return -1, nil
	}
	return n, err
}

func (s *udpState) drop(from wire.Addr, err error) {
	if !s.tr.hasDroppedHook() {
		return
	}
	s.tr.droppedDatagram(from, neterr.Truncated(wire.StageUDPHeader, err))
}

func (s *udpState) writeTo(b []byte, to wire.Addr, addr net.Addr) (int, error) {
	errAddr := func() net.Addr {
		if addr == nil && to.IsValid() {
			return to
		}
		return addr
	}
	switch {
	case !to.IsValid():
		return 0, s.newErr("write", addr, syscall.EINVAL)
	case !matchesFamily(s.network, to.IP()):
		return 0, s.newErr("write", errAddr(), familyErr(s.network, to.String()))
	case len(b) > s.maxLen-wire.UDPHeaderLen(to):
		return 0, s.newErr("write", errAddr(), errMsgSize)
	case s.dead():
		return 0, s.newErr("write", errAddr(), errNoUDPConn)
	}
	s.wmu.Lock()
	buf, _ := wire.AppendUDPHeader(s.wbuf[:0], 0, to) // to is valid
	buf = append(buf, b...)
	s.wbuf = buf
	var err error
	switch {
	case s.relay != nil:
		_, err = s.relay.Write(buf)
	case s.upc != nil:
		_, err = s.upc.WriteToUDPAddrPort(buf, s.relayAP)
	default:
		_, err = s.pc.WriteTo(buf, s.relayAddr)
	}
	s.wmu.Unlock()
	if err != nil {
		return 0, s.ioErr("write", errAddr(), err)
	}
	return len(b), nil
}

const refusedWait = 50 * time.Millisecond

// awaitEnd: the relay's ICMP port unreachable may beat the control conn's EOF.
func (s *udpState) awaitEnd() {
	t := time.NewTimer(refusedWait)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
	}
}

func (s *udpState) ioErr(op string, addr net.Addr, err error) error {
	if !s.closed.Load() && errnoKind(err) == KindRefused {
		s.awaitEnd()
	}
	s.mu.Lock()
	ended := s.err
	s.mu.Unlock()
	switch {
	case s.closed.Load():
		err = net.ErrClosed
	case ended != nil:
		err = ended
	default:
		if oe, ok := err.(*net.OpError); ok {
			err = oe.Err
		}
	}
	return s.newErr(op, addr, err)
}

func (s *udpState) newErr(op string, addr net.Addr, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: s.laddr, Addr: addr, Err: err}
}
