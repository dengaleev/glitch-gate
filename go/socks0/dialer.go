package socks0

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Resolver resolves target names locally; *net.Resolver and *Dialer (Tor
// RESOLVE) implement it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer dials through a SOCKS proxy; it fits http.Transport.DialContext and
// x/net/proxy. Safe for concurrent use; do not modify it after first use.
type Dialer struct {
	ProxyAddr string

	// ProxyDial connects to the proxy ("tcp"): chains, TLS, FastOpenDial. nil is
	// the zero net.Dialer.
	ProxyDial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Resolver, if set, resolves target names locally (first address of the
	// family, no fallback); nil sends names to the proxy. Failures are at
	// StageResolve; a Dialer's *net.DNSError is copied without its UnwrapErr chain.
	Resolver Resolver

	Config *Config

	// RelayDial connects to the UDP relay; the conn must keep datagram boundaries.
	// Security: a BND name reaches it unresolved and unchecked by the relay
	// address policy (see UDPConn). nil applies the policy to resolved IPs too.
	RelayDial func(ctx context.Context, network, addr string) (net.Conn, error)

	// RelayListen, instead of RelayDial, opens an unconnected socket for proxies
	// that answer from another port than BND (NAT); datagrams are accepted from
	// the relay's IP, any port. Setting both is a config error.
	RelayListen func(ctx context.Context, network, laddr string) (net.PacketConn, error)

	// RelayUseProxyHost replaces any BND IP, not only an unspecified one, with the
	// proxy's host: for NATed servers reporting a private IP.
	RelayUseProxyHost bool

	// AssociateAddr is DST of DialContext's UDP ASSOCIATE; "" is 0.0.0.0:0, which
	// works behind NAT. A non-zero port needs RelayDial or RelayListen.
	AssociateAddr string

	// AssociateLocalPort sends the pre-opened relay socket's port as DST, so a
	// server honouring DST.PORT rejects IP-spoofed datagrams. Breaks behind
	// port-changing NAT; a config error with RelayDial or an explicit DST.
	AssociateLocalPort bool
}

var errNoProxyConn = errors.New("socks0: ProxyDial returned no conn and no error")

// DialContext dials addr: "tcp*" by CONNECT, "udp*" by UDP ASSOCIATE (a
// *UDPConn, connected like net.DialUDP). A 4/6 suffix restricts the family.
// ModeSequential and ModePipelined return after the reply, with ProxyDial's
// conn as is (a *net.TCPConn by default) and its deadlines cleared; ModeEarly
// returns a *Conn before the CONNECT. ctx and HandshakeTimeout bound the
// dial, not the returned conn. Errors are *net.OpError{Op: "socks connect"}
// wrapping a *HandshakeError (and ctx.Err() on cancellation); on error no
// conn is left open.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		target, err := d.parseTarget(network, addr)
		var dst string
		if d != nil {
			dst = d.AssociateAddr
		}
		c, err := d.associate(ctx, network, target, err, dst)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	target, err := d.parseTarget(network, addr)
	if d != nil && d.Config != nil && d.Config.Mode == ModeEarly {
		return d.dialEarly(ctx, network, target, err)
	}
	var c Conn // the handshake state, on the stack: the conn is returned as is
	if _, err := d.newConn(&ctx, &c, opConnect, network, wire.CmdConnect, target, err); err != nil {
		return nil, err
	}
	conn, _, err := d.connect(ctx, &c)
	return conn, err
}

func (d *Dialer) dialEarly(ctx context.Context, network string, target wire.Addr, err error) (net.Conn, error) {
	c := new(Conn)
	c.h.buf = c.inline[:0]
	if _, err := d.newConn(&ctx, c, opConnect, network, wire.CmdConnect, target, err); err != nil {
		return nil, err
	}
	conn, _, err := d.connect(ctx, c)
	if err != nil {
		return nil, err
	}
	c.conn, c.traceSet, c.h.mu = conn, true, &c.mu
	return c, nil
}

const (
	opConnect    = "socks connect"
	opBind       = "socks bind"
	opAssociate  = "socks udp associate"
	opResolve    = "socks resolve"
	opResolvePTR = "socks resolve ptr"
)

func opOf(cmd wire.Command) string {
	switch cmd {
	case wire.CmdConnect:
		return opConnect
	case wire.CmdBind:
		return opBind
	case wire.CmdUDPAssociate:
		return opAssociate
	case wire.CmdTorResolve:
		return opResolve
	case wire.CmdTorResolvePTR:
		return opResolvePTR
	}
	return "socks " + cmd.String()
}

// newConn validates arguments (err: target's parse error) and Config, and
// resolves the target with d.Resolver.
func (d *Dialer) newConn(ctx *context.Context, c *Conn, op, network string, cmd wire.Command, target wire.Addr, err error) (resolved wire.Addr, _ error) {
	if *ctx == nil {
		*ctx = context.Background()
	}
	c.network, c.op, c.h.target = network, op, target
	if d == nil {
		return target, c.opError(&HandshakeError{StageConfig, errors.New("socks0: nil Dialer")})
	}
	c.proxy, _ = wire.ParseAddr(d.ProxyAddr)
	if err == nil {
		err = c.init(d.Config, cmd, target)
	}
	if err == nil && c.h.version == 4 && network == "tcp6" {
		err = errors.New("socks0: SOCKS4 has no IPv6")
	}
	if err != nil {
		return target, c.opError(&HandshakeError{StageConfig, err})
	}
	if d.Resolver == nil || !target.IsName() || cmd == wire.CmdTorResolve {
		return target, nil
	}
	return d.resolveTarget(*ctx, c, network, target)
}

func (d *Dialer) resolveTarget(ctx context.Context, c *Conn, network string, target wire.Addr) (wire.Addr, error) {
	if c.h.version == 4 {
		network = "tcp4"
	}
	ip, err := d.resolve(ctx, network, target.Name())
	if err != nil {
		return target, c.opError(&HandshakeError{StageResolve, resolveErr(ctx, err)})
	}
	resolved := addrPort(ip, target.Port())
	if err := c.h.setTarget(resolved); err != nil {
		return target, c.opError(&HandshakeError{StageConfig, err}) // SOCKS4 and 0.0.0.0/24
	}
	c.h.target = target // errors name the target asked for
	return resolved, nil
}

// connect dials the proxy and, except in ModeEarly, runs the handshake; on
// error the conn is closed.
func (d *Dialer) connect(ctx context.Context, c *Conn) (net.Conn, tracer, error) {
	ctx, cancel, connTimeout := d.dialTimeout(ctx, c.handshakeTimeout)
	if cancel != nil {
		defer cancel()
	}
	tr := newTracer(ctx, c.configTrace)
	conn, err := d.dialProxy(ctx, tr)
	if err != nil {
		return nil, tr, c.opError(&HandshakeError{StageProxyDial, ctxErr(ctx, err)})
	}
	c.trace = tr
	if c.h.mode == ModeEarly {
		conn.SetDeadline(time.Time{})
		return conn, tr, nil
	}
	var deadline time.Time
	if connTimeout > 0 {
		deadline = time.Now().Add(connTimeout)
		conn.SetDeadline(deadline)
	}
	if err := c.handshakeOver(ctx, conn, tr, conn.Close, deadline); err != nil {
		return nil, tr, err
	}
	conn.SetDeadline(time.Time{})
	return conn, tr, nil
}

// dialTimeout: the built-in dial gets a conn deadline (no per-dial timer
// ctx); a ProxyDial can tarpit (TLS, a chain), so it gets the ctx.
func (d *Dialer) dialTimeout(ctx context.Context, t time.Duration) (_ context.Context, cancel context.CancelFunc, connTimeout time.Duration) {
	if t == 0 && d.ProxyDial == nil && !hasDeadline(ctx) {
		return ctx, nil, defaultHandshakeTimeout
	}
	ctx, cancel = handshakeCtx(ctx, t)
	return ctx, cancel, 0
}

func (d *Dialer) dialProxy(ctx context.Context, tr tracer) (net.Conn, error) {
	tr.connectStart("tcp", d.ProxyAddr)
	dial := d.ProxyDial
	if dial == nil {
		dial = new(net.Dialer).DialContext
	}
	conn, err := dial(ctx, "tcp", d.ProxyAddr)
	err = dialErr(conn, err, errNoProxyConn)
	tr.connectDone("tcp", d.ProxyAddr, err)
	if err == nil && ctx.Err() != nil { // a ProxyDial that ignores ctx
		conn.Close()
		err = ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// dialErr handles a dial func that returned neither or both of conn and err.
func dialErr(conn io.Closer, err, errNone error) error {
	switch {
	case err == nil && conn == nil:
		return errNone
	case err != nil && conn != nil:
		conn.Close()
	}
	return err
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) parseTarget(network, addr string) (wire.Addr, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return wire.Addr{}, net.UnknownNetworkError(network)
	}
	a, err := wire.ParseAddr(addr)
	if err != nil {
		return wire.Addr{}, err
	}
	if !matchesFamily(network, a.IP()) {
		return a, &net.AddrError{Err: "address family mismatch for " + network, Addr: addr}
	}
	return a, nil
}

func (d *Dialer) resolve(ctx context.Context, network, host string) (netip.Addr, error) {
	ips, err := d.Resolver.LookupNetIP(ctx, "ip"+network[len("tcp"):], host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.IsValid() && matchesFamily(network, ip) {
			return ip, nil
		}
	}
	return netip.Addr{}, &net.DNSError{Err: "no suitable address found", Name: host, IsNotFound: true}
}

// resolveErr strips a RESOLVE's chain so its errors are not this dial's.
func resolveErr(ctx context.Context, err error) error {
	err = ctxErr(ctx, err)
	de, ok := err.(*net.DNSError)
	if !ok || !hasErrType[*HandshakeError](de.UnwrapErr) {
		return err
	}
	cp := *de
	cp.UnwrapErr = nil
	for _, cerr := range [...]error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(de.UnwrapErr, cerr) {
			cp.UnwrapErr = cerr
		}
	}
	return &cp
}

func ctxErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		return cerr
	}
	return err
}

func matchesFamily(network string, ip netip.Addr) bool {
	switch network[len(network)-1] {
	case '4':
		return !ip.Is6()
	case '6':
		return !ip.Is4()
	}
	return true
}

func addrPort(ip netip.Addr, port uint16) wire.Addr {
	return wire.AddrFromAddrPort(netip.AddrPortFrom(ip, port))
}
