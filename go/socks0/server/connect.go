package server

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Mux routes by command; a nil entry replies 07 and returns an error matching errors.ErrUnsupported.
type Mux struct {
	Connect   Handler // CmdConnect (SOCKS4 too)
	Bind      Handler // CmdBind (SOCKS4 too)
	Associate Handler // CmdUDPAssociate (SOCKS5 only)
	Resolve   Handler // CmdTorResolve, CmdTorResolvePTR (SOCKS5 only)
}

func (m *Mux) ServeSOCKS(ctx context.Context, r *Request) error {
	var h Handler
	switch r.Command {
	case wire.CmdConnect:
		h = m.Connect
	case wire.CmdBind:
		h = m.Bind
	case wire.CmdUDPAssociate:
		h = m.Associate
	case wire.CmdTorResolve, wire.CmdTorResolvePTR:
		h = m.Resolve
	}
	if h == nil { // SOCKS4 never gets here with another command: authorize4 rejects it
		return notSupported(r)
	}
	return h.ServeSOCKS(ctx, r)
}

func (m *Mux) validate() error {
	if m != nil {
		for _, h := range [...]Handler{m.Connect, m.Bind, m.Associate, m.Resolve} {
			if err := validate(h); err != nil {
				return err
			}
		}
	}
	return nil
}

func notSupported(r *Request) error {
	if _, err := r.Reply(wire.ReplyCommandNotSupported, wire.Addr{}); err != nil {
		if _, replied := errors.AsType[*socks0.ReplyError](err); !replied {
			return err
		}
	}
	return errUnsupported
}

// ConnectHandler dials r.Addr, replies with BND set to the target conn's local address and relays.
// A name the Filter denies gets 04, not 02, so internal names look unknown.
type ConnectHandler struct {
	// Dial replaces Dialer and owns the target policy: Filter is NOT applied (see Filter.Control).
	// Use it for upstream proxies; for socket options or an egress address set Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Dialer is copied; its ControlContext runs after Filter and the own-host check, which every
	// address it tries passes before any packet: the checked IP is the one connected to (no SSRF via
	// DNS rebinding, no port-scan oracle). nil means a zero net.Dialer. On plan9, which runs no
	// Control, a name is resolved first with its Resolver and the addresses that pass are dialed.
	Dialer *net.Dialer

	// Filter vets each address dialed when Dial is nil; nil means DefaultFilter.
	Filter Filter

	// DialTimeout zero means 30 s; negative, none.
	DialTimeout time.Duration

	Relayer Relayer
}

// ServeSOCKS replies 07 to other commands.
func (h *ConnectHandler) ServeSOCKS(ctx context.Context, r *Request) error {
	if r.Command != wire.CmdConnect {
		return notSupported(r)
	}
	t, err := h.dial(ctx, r)
	if err != nil {
		if r.Addr.IsName() && errors.Is(err, ErrNotAllowed) {
			_, _ = r.Reply(wire.ReplyHostUnreachable, wire.Addr{})
		}
		return err
	}
	c, err := r.Reply(wire.ReplySucceeded, wire.AddrFromAddrPort(addrPortOf(t.LocalAddr())))
	if err != nil {
		t.Close()
		return err
	}
	_, _, err = h.Relayer.Relay(ctx, c, t)
	return err
}

const defaultDialTimeout = 30 * time.Second

func (h *ConnectHandler) dial(ctx context.Context, r *Request) (net.Conn, error) {
	timeout := orDefault(h.DialTimeout, defaultDialTimeout)
	if h.Dial != nil {
		return h.dialCustom(ctx, r, timeout)
	}
	return h.dialFiltered(ctx, r, timeout)
}

func (h *ConnectHandler) dialCustom(ctx context.Context, r *Request, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return h.Dial(ctx, "tcp", r.Addr.String())
}

func (h *ConnectHandler) dialFiltered(ctx context.Context, r *Request, timeout time.Duration) (net.Conn, error) {
	var d net.Dialer
	if h.Dialer != nil {
		d = *h.Dialer
	}
	if timeout > 0 && (d.Timeout == 0 || timeout < d.Timeout) {
		d.Timeout = timeout // net.Dialer derives its one deadline ctx from it
	}
	t, err := h.dialChecked(ctx, r, &d)
	if err != nil {
		return nil, err
	}
	// Local IP == remote IP: this host, by an address the listing missed.
	remote := addrPortOf(t.RemoteAddr())
	if err := h.Filter.checkOwnHost(r, tcpNetwork(remote.Addr()), addrPortOf(t.LocalAddr()), remote, t.RemoteAddr()); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// controlSupported: net.Dialer runs Control and ControlContext, except on plan9. (On js and wasip1
// a dial that sets them fails, which fails closed.)
const controlSupported = runtime.GOOS != "plan9"

// dialChecked dials r.Addr, vetting every address it tries before any packet is sent to it.
func (h *ConnectHandler) dialChecked(ctx context.Context, r *Request, d *net.Dialer) (net.Conn, error) {
	switch {
	case h.vetEarly(r, d):
	case !controlSupported:
		return h.dialVetted(ctx, r, d, d.Resolver) // a nil *net.Resolver is the default one
	default:
		d.ControlContext = h.Filter.dialControl(r, d.ControlContext, d.Control)
		d.Control = nil
	}
	return d.DialContext(ctx, "tcp", r.Addr.String())
}

// dialVetted is dialChecked without Control: it resolves a name with res, vets each IP with
// Filter and the own-host check, and dials those that pass in order, each as vetted (no DNS
// rebinding), within d.Timeout as a whole. Errors are the first denial or lookup error if no IP
// passed, else the first dial error.
func (h *ConnectHandler) dialVetted(ctx context.Context, r *Request, d *net.Dialer, res socks0.Resolver) (net.Conn, error) {
	if d.Timeout > 0 { // it includes the lookup, as net.Dialer's does
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	ips, err := h.vettedIPs(ctx, r, res)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
	}
	var first error
	for _, ip := range ips {
		t, err := d.DialContext(ctx, tcpNetwork(ip), netip.AddrPortFrom(ip, r.Addr.Port()).String())
		if err == nil {
			return t, nil
		}
		first = cmp.Or(first, err)
	}
	return nil, first
}

// vettedIPs returns r.Addr's IP, or its name's addresses, that pass Filter and the own-host check.
func (h *ConnectHandler) vettedIPs(ctx context.Context, r *Request, res socks0.Resolver) ([]netip.Addr, error) {
	if ip := r.Addr.IP(); ip.IsValid() {
		ip = ip.Unmap().WithZone("")
		return []netip.Addr{ip}, h.Filter.vet(r, tcpNetwork(ip), netip.AddrPortFrom(ip, r.Addr.Port()))
	}
	ips, err := res.LookupNetIP(ctx, "ip", r.Addr.Name())
	var vetted []netip.Addr
	var denial error
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		if verr := h.Filter.vet(r, tcpNetwork(ip), netip.AddrPortFrom(ip, r.Addr.Port())); verr != nil {
			denial = cmp.Or(denial, verr)
			continue
		}
		vetted = append(vetted, ip)
	}
	if len(vetted) != 0 {
		return vetted, nil
	}
	return nil, cmp.Or(denial, err, notFound(r.Addr.Name()))
}

// vetEarly reports whether an IP literal passed Filter and the own-host check with the network and
// address Control would get, so that d needs no ControlContext (no closure, no address string). A
// name keeps ControlContext (DNS rebinding); a denial does too, so that the dial fails as before.
func (h *ConnectHandler) vetEarly(r *Request, d *net.Dialer) bool {
	ip := r.Addr.IP()
	if !ip.IsValid() || ip.IsUnspecified() || d.Control != nil || d.ControlContext != nil || d.LocalAddr != nil {
		return false // unspecified: some systems dial loopback instead; LocalAddr may change the family
	}
	return h.Filter.vet(r, tcpNetwork(ip), netip.AddrPortFrom(ip, r.Addr.Port())) == nil
}

func (f Filter) dialControl(r *Request, inner func(context.Context, string, string, syscall.RawConn) error, innerCtl func(string, string, syscall.RawConn) error) func(context.Context, string, string, syscall.RawConn) error {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if err := f.checkDial(r, network, address); err != nil {
			return err
		}
		switch {
		case inner != nil:
			return inner(ctx, network, address, c)
		case innerCtl != nil:
			return innerCtl(network, address, c)
		}
		return nil
	}
}

func tcpNetwork(ip netip.Addr) string {
	if ip.Is4() {
		return "tcp4"
	}
	return "tcp6"
}
