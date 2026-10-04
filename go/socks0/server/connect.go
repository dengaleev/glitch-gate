package server

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
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
	if h == nil || r.Version == V4 && r.Command != wire.CmdConnect && r.Command != wire.CmdBind {
		return notSupported(r)
	}
	return h.ServeSOCKS(ctx, r)
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
	// DNS rebinding, no port-scan oracle). nil means a zero net.Dialer.
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
	timeout := cmp.Or(h.DialTimeout, defaultDialTimeout)
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
	d.ControlContext = h.Filter.dialControl(r, d.ControlContext, d.Control)
	d.Control = nil
	t, err := d.DialContext(ctx, "tcp", r.Addr.String())
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
