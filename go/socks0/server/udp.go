package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/internal/neterr"
	"github.com/dengaleev/glitch-gate/go/socks0/internal/sockopt"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// AssociateHandler serves UDP ASSOCIATE with two sockets and two goroutines per association,
// which lives as long as the control conn (or until IdleTimeout or Close).
//
// Client datagrams are accepted only from the control conn's peer IP, and from DST.PORT if
// non-zero (with DST.ADDR that IP or unspecified), else from the source port of the first valid
// datagram. UDP proves no source: a host that forges or shares the client's IP (no BCP 38, CGNAT)
// can win that lock. Clients should send their source port as DST (socks0.Dialer's
// AssociateLocalPort), or tunnel UDP over TCP for a trustworthy source.
//
// Bad, fragmented or buffer-sized datagrams are dropped (ServerTrace.Dropped). Names are cached
// 60 s, failures too, counting toward MaxTargets; Filter judges each IP:port once and that IP is
// the one sent to. With *net.UDPConn sockets the relay allocates nothing per datagram.
type AssociateHandler struct {
	// ListenClient defaults to "udp" on r.LocalAddr's IP, port 0.
	ListenClient func(ctx context.Context, network, address string) (net.PacketConn, error)

	// ListenTarget defaults to "udp" on ":0" with SO_BROADCAST cleared.
	ListenTarget func(ctx context.Context, network, address string) (net.PacketConn, error)

	Resolver  socks0.Resolver // target names; nil means net.DefaultResolver; lookups time out after 5 s
	Filter    Filter          // each target IP:port after resolution; nil means DefaultFilter
	Filtering Filtering       // which target datagrams reach the client; zero is AddressAndPortDependent

	// Advertise returns BND for relay; nil means relay with an unspecified IP replaced by
	// r.LocalAddr's. Override it behind NAT.
	Advertise func(r *Request, relay netip.AddrPort) wire.Addr

	IdleTimeout time.Duration // no datagram relayed either way → end; zero means 5 min, negative none; dropped datagrams do not count
	MaxDatagram int           // whole datagram incl. header, both ways; zero means 4096 + wire.MaxUDPHeaderLen; larger ones dropped; negative or 1–22 (under the IPv6 header) is a config error
	MaxTargets  int           // distinct target IP:ports and names per association; zero means 1024; beyond, dropped; negative is a config error
}

const minDatagram = headroom + 1

func (h *AssociateHandler) validate() error {
	switch {
	case h == nil:
	case h.MaxDatagram < 0 || h.MaxDatagram > 0 && h.MaxDatagram < minDatagram:
		return fmt.Errorf("socks0/server: AssociateHandler.MaxDatagram %d: negative or under %d", h.MaxDatagram, minDatagram)
	case h.MaxTargets < 0:
		return fmt.Errorf("socks0/server: AssociateHandler.MaxTargets %d: negative", h.MaxTargets)
	}
	return nil
}

// Filtering is the RFC 4787 inbound filtering of target→client datagrams.
type Filtering uint8

const (
	AddressAndPortDependent Filtering = iota // only from IP:ports the client sent to
	AddressDependent                         // from any port of an IP the client sent to
	EndpointIndependent                      // from anyone ("full cone"): STUN/P2P; widest surface
)

const (
	nameTTL            = 60 * time.Second
	lookupTimeout      = 5 * time.Second
	headroom           = 3 + 1 + 16 + 2 // the longest header in front of a target datagram (IPv6 source)
	defaultMaxDatagram = 4096 + wire.MaxUDPHeaderLen
	defaultMaxTargets  = 1024
	defaultUDPIdle     = 5 * time.Minute
)

// ServeSOCKS replies 07 to other commands.
func (h *AssociateHandler) ServeSOCKS(ctx context.Context, r *Request) error {
	if r.Command != wire.CmdUDPAssociate { // not a SOCKS4 command
		return notSupported(r)
	}
	if err := h.validate(); err != nil { // behind a Handler the Server cannot see
		return &socks0.HandshakeError{Stage: socks0.StageConfig, Err: err}
	}
	client, target, err := h.listen(ctx, r)
	if err != nil {
		return err
	}
	c, err := r.Reply(wire.ReplySucceeded, advertised(h.Advertise, r, addrPortOf(client.LocalAddr())))
	if err != nil {
		client.Close()
		target.Close()
		return err
	}
	return h.newAssociation(ctx, r, client, target).run(c)
}

func (h *AssociateHandler) listen(ctx context.Context, r *Request) (client, target net.PacketConn, err error) {
	client, err = listenOr(h.ListenClient, listenUDP)(ctx, "udp", hostPort(ipOf(r.LocalAddr), 0))
	if err != nil {
		return nil, nil, err
	}
	target, err = listenOr(h.ListenTarget, sockopt.ListenNoBroadcast)(ctx, "udp", ":0")
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return client, target, nil
}

func (h *AssociateHandler) newAssociation(ctx context.Context, r *Request, client, target net.PacketConn) *association {
	a := &association{
		ctx: ctx, r: r, trace: r.sc.s.Trace, filter: h.Filter, filtering: h.Filtering,
		resolver: h.Resolver, client: client, target: target,
		maxDatagram: min(orDefault(h.MaxDatagram, defaultMaxDatagram), headroom+65535),
		maxTargets:  orDefault(h.MaxTargets, defaultMaxTargets),
		idle:        orDefault(h.IdleTimeout, defaultUDPIdle),
		clientIP:    ipOf(r.RemoteAddr),
		targets:     make(map[netip.AddrPort]error),
		ips:         make(map[netip.Addr]struct{}),
		names:       make(map[string]nameEntry),
	}
	if a.resolver == nil {
		a.resolver = net.DefaultResolver
	}
	if ip := r.Addr.IP(); ip.IsValid() && (ip == a.clientIP || ip.IsUnspecified()) {
		a.clientPort.Store(uint32(r.Addr.Port())) // 0: the first datagram locks it
	}
	a.lastMove.Store(time.Now().UnixNano())
	return a
}

func listenOr(f, def func(context.Context, string, string) (net.PacketConn, error)) func(context.Context, string, string) (net.PacketConn, error) {
	if f != nil {
		return f
	}
	return def
}

func listenUDP(ctx context.Context, network, address string) (net.PacketConn, error) {
	return new(net.ListenConfig).ListenPacket(ctx, network, address)
}

func advertised(custom func(*Request, netip.AddrPort) wire.Addr, r *Request, ap netip.AddrPort) wire.Addr {
	if custom != nil {
		return custom(r, ap)
	}
	if ip := ipOf(r.LocalAddr); ap.Addr().IsUnspecified() && ip.IsValid() {
		ap = netip.AddrPortFrom(ip, ap.Port())
	}
	return wire.AddrFromAddrPort(ap)
}

func hostPort(ip netip.Addr, port uint16) string {
	if !ip.IsValid() {
		return ":0"
	}
	return netip.AddrPortFrom(ip, port).String()
}

type association struct {
	ctx         context.Context
	r           *Request
	trace       *ServerTrace
	filter      Filter
	filtering   Filtering
	resolver    socks0.Resolver
	maxDatagram int
	maxTargets  int
	idle        time.Duration

	client, target net.PacketConn
	clientIP       netip.Addr
	clientPort     atomic.Uint32 // 0 until locked
	lastMove       atomic.Int64  // UnixNano of the last datagram relayed either way
	panicked       atomic.Bool

	mu      sync.RWMutex // guards targets and ips; written by up only
	targets map[netip.AddrPort]error
	ips     map[netip.Addr]struct{}

	// Owned by the up goroutine.
	names      map[string]nameEntry
	prevHeader headerVerdict
}

type headerVerdict struct {
	raw     [wire.MaxUDPHeaderLen]byte
	n       int
	dst     netip.AddrPort
	err     error
	expires time.Time // for a name; zero for an IP
}

type nameEntry struct {
	ip  netip.Addr
	err error
	exp time.Time
}

func (a *association) run(c *Conn) error {
	var wg sync.WaitGroup
	wg.Go(func() { defer a.recover(c); a.up() })
	wg.Go(func() { defer a.recover(c); a.down() })
	err := a.watchControl(c)
	a.client.Close()
	a.target.Close()
	wg.Wait()
	if a.panicked.Load() {
		return errRelayPanic
	}
	return err
}

var errRelayPanic = errors.New("socks0/server: UDP relay panicked")

// recover ends the association on a relay goroutine panic (a Filter or Resolver bug), not the process.
func (a *association) recover(c *Conn) {
	p := recover()
	if p == nil {
		return
	}
	a.panicked.Store(true)
	a.r.sc.s.logf("socks0/server: panic in UDP relay for %v: %q\n%s", a.r.RemoteAddr, fmt.Sprint(p), debug.Stack())
	a.client.Close()
	a.target.Close()
	c.Close()
}

// watchControl discards the control conn's bytes (I5's one exception) until it ends.
func (a *association) watchControl(c *Conn) error {
	defer context.AfterFunc(a.ctx, func() { c.Close() })()
	b := getBuffers()
	defer putBuffers(b)
	for {
		if a.idle > 0 {
			_ = c.SetReadDeadline(time.Unix(0, a.lastMove.Load()).Add(a.idle))
		}
		_, err := b.read(c, 0)
		switch {
		case err == nil:
		case a.ctx.Err() != nil:
			return a.ctx.Err()
		case errors.Is(err, io.EOF):
			return nil
		case a.idle > 0 && errors.Is(err, os.ErrDeadlineExceeded):
			if time.Since(time.Unix(0, a.lastMove.Load())) >= a.idle {
				return nil
			}
		default:
			return err
		}
	}
}

func (a *association) drop(from netip.AddrPort, err error) { a.trace.dropped(a.ctx, from, err) }

func (a *association) up() {
	bp := getDatagram(a.maxDatagram)
	defer datagramPool.Put(bp)
	buf := *bp
	for {
		n, from, err := readFrom(a.client, buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		port := uint16(a.clientPort.Load())
		if from.Addr() != a.clientIP || port != 0 && from.Port() != port {
			a.drop(from, ErrWrongSource)
			continue
		}
		if n == len(buf) {
			a.drop(from, ErrTooLarge)
			continue
		}
		dst, hl, err := a.header(buf[:n])
		if err != nil {
			a.drop(from, err)
			continue
		}
		if port == 0 {
			a.clientPort.Store(uint32(from.Port()))
		}
		a.lastMove.Store(time.Now().UnixNano()) // only relayed datagrams keep the association (S7)
		_, _ = writeTo(a.target, buf[hl:n], dst)
	}
}

func (a *association) down() {
	bp := getDatagram(a.maxDatagram)
	defer datagramPool.Put(bp)
	buf := *bp
	for {
		n, from, err := readFrom(a.target, buf[headroom:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		port := uint16(a.clientPort.Load())
		switch {
		case port == 0 || !a.solicited(from):
			a.drop(from, ErrUnsolicited)
			continue
		case n == len(buf)-headroom:
			a.drop(from, ErrTooLarge)
			continue
		}
		a.lastMove.Store(time.Now().UnixNano())
		_, _ = writeTo(a.client, frame(buf, from, n), netip.AddrPortFrom(a.clientIP, port))
	}
}

// frame writes the header right before the payload at buf[headroom:]: no payload copy.
func frame(buf []byte, from netip.AddrPort, n int) []byte {
	src := wire.AddrFromAddrPort(from)
	start := headroom - wire.UDPHeaderLen(src)
	_, _ = wire.AppendUDPHeader(buf[start:start:headroom], 0, src)
	return buf[start : headroom+n]
}

func (a *association) solicited(from netip.AddrPort) bool {
	if a.filtering == EndpointIndependent {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.filtering == AddressDependent {
		_, ok := a.ips[from.Addr()]
		return ok
	}
	err, ok := a.targets[from]
	return ok && err == nil
}

// header reuses the previous header's result on a repeat: no allocation, lookup or Filter call.
func (a *association) header(p []byte) (netip.AddrPort, int, error) {
	if prev := &a.prevHeader; prev.matches(p) {
		return prev.dst, prev.n, prev.err
	}
	addr, hl, err := parseClientHeader(p)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	dst, expires, err := a.judge(addr)
	if err == ErrTooManyTargets {
		return dst, hl, err // not cached: may pass later for a known target
	}
	a.prevHeader.n = copy(a.prevHeader.raw[:], p[:hl])
	a.prevHeader.dst, a.prevHeader.err, a.prevHeader.expires = dst, err, expires
	return dst, hl, err
}

func (v *headerVerdict) matches(p []byte) bool {
	return v.n > 0 && bytes.HasPrefix(p, v.raw[:v.n]) && (v.expires.IsZero() || time.Now().Before(v.expires))
}

func parseClientHeader(p []byte) (wire.Addr, int, error) {
	frag, addr, hl, err := wire.ParseUDPHeader(p)
	switch {
	case err != nil:
		return wire.Addr{}, 0, neterr.Truncated(wire.StageUDPHeader, err)
	case frag != 0:
		return wire.Addr{}, 0, ErrFragment
	}
	return addr, hl, nil
}

func (a *association) judge(addr wire.Addr) (dst netip.AddrPort, expires time.Time, err error) {
	ip := addr.IP()
	if addr.IsName() {
		e, err := a.lookup(addr.Name(), addr.Port())
		if err != nil {
			return netip.AddrPort{}, time.Time{}, err
		}
		if e.err != nil {
			return netip.AddrPortFrom(e.ip, addr.Port()), e.exp, e.err
		}
		ip, expires = e.ip, e.exp
	}
	dst = netip.AddrPortFrom(ip, addr.Port())
	return dst, expires, a.admit(dst)
}

// lookup counts every name toward MaxTargets, failures too (S6).
func (a *association) lookup(name string, port uint16) (nameEntry, error) {
	now := time.Now()
	e, ok := a.names[name]
	if ok && now.Before(e.exp) {
		return e, nil
	}
	if !ok && a.full() {
		return e, ErrTooManyTargets
	}
	e = a.resolve(name, port)
	e.exp = now.Add(nameTTL)
	a.names[name] = e
	return e, nil
}

// resolve: a denial beats a lookup *net.DNSError, any other lookup error beats a denial.
func (a *association) resolve(name string, port uint16) nameEntry {
	ctx, cancel := context.WithTimeout(a.ctx, lookupTimeout)
	var one [1]netip.Addr
	ips, denial, err := a.filter.lookupAllowed(ctx, a.resolver, a.r, name, port, udpNetwork, one[:0])
	cancel()
	_, dns := err.(*net.DNSError)
	switch {
	case len(ips) > 0:
		return nameEntry{ip: ips[0]}
	case denial != nil && (err == nil || dns):
		return nameEntry{err: denial}
	case err != nil:
		return nameEntry{err: err}
	}
	return nameEntry{err: notFound(name)}
}

func (a *association) admit(dst netip.AddrPort) error {
	a.mu.RLock()
	err, ok := a.targets[dst]
	a.mu.RUnlock()
	if ok {
		return err
	}
	if !dst.Addr().IsValid() {
		return &DeniedError{Addr: dst, Reason: "invalid"}
	}
	if a.full() {
		return ErrTooManyTargets
	}
	err = a.filter.vet(a.r, udpNetwork(dst.Addr()), dst)
	a.mu.Lock()
	a.targets[dst] = err
	if err == nil {
		a.ips[dst.Addr()] = struct{}{}
	}
	a.mu.Unlock()
	return err
}

func (a *association) full() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.targets)+len(a.names) >= a.maxTargets
}

func udpNetwork(ip netip.Addr) string {
	if ip.Is4() {
		return "udp4"
	}
	return "udp6"
}

func readFrom(pc net.PacketConn, b []byte) (int, netip.AddrPort, error) {
	if u, ok := pc.(*net.UDPConn); ok {
		n, ap, err := u.ReadFromUDPAddrPort(b)
		return n, normalize(ap), err
	}
	n, addr, err := pc.ReadFrom(b)
	return n, addrPortOf(addr), err
}

func writeTo(pc net.PacketConn, b []byte, ap netip.AddrPort) (int, error) {
	if u, ok := pc.(*net.UDPConn); ok {
		return u.WriteToUDPAddrPort(b, ap)
	}
	return pc.WriteTo(b, net.UDPAddrFromAddrPort(ap))
}

var datagramPool sync.Pool

func getDatagram(size int) *[]byte {
	if p, ok := datagramPool.Get().(*[]byte); ok && cap(*p) >= size {
		*p = (*p)[:size]
		return p
	}
	return new(make([]byte, size))
}
