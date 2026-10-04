package socks0

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var _ Resolver = (*Dialer)(nil)

// LookupNetIP resolves host at the proxy with Tor's RESOLVE (Config.Auth
// applies, so IsolateSOCKSAuth keeps the circuit). IP literals return at
// once; ModeEarly runs as ModePipelined. Errors are *net.DNSError wrapping a
// *net.OpError{Op: "socks resolve"}. IsNotFound (REP 04) can be transient on
// Tor: do not cache it as a negative answer.
func (d *Dialer) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var err error
	switch network {
	case "ip", "ip4", "ip6":
	default:
		err = net.UnknownNetworkError(network)
	}
	if ip, perr := netip.ParseAddr(host); perr == nil && err == nil {
		if ip = ip.Unmap(); !matchesFamily(network, ip) {
			return nil, d.notFound(host)
		}
		return []netip.Addr{ip}, nil
	}
	var target wire.Addr
	if err == nil {
		target, err = wire.ParseAddr(net.JoinHostPort(host, "0"))
	}
	bound, err := d.lookup(ctx, opResolve, wire.CmdTorResolve, host, target, err)
	if err != nil {
		return nil, err
	}
	if ip := bound.IP(); matchesFamily(network, ip) {
		return []netip.Addr{ip}, nil
	}
	return nil, d.notFound(host)
}

func (d *Dialer) LookupHost(ctx context.Context, host string) ([]string, error) {
	ips, err := d.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return []string{ips[0].String()}, nil
}

// LookupAddr uses Tor's RESOLVE_PTR; names have no trailing dot.
func (d *Dialer) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, &net.DNSError{Err: "unrecognized address", Name: addr, Server: d.server()}
	}
	bound, err := d.lookup(ctx, opResolvePTR, wire.CmdTorResolvePTR, addr, addrPort(ip, 0), nil)
	if err != nil {
		return nil, err
	}
	return []string{bound.Name()}, nil
}

func (d *Dialer) lookup(ctx context.Context, op string, cmd wire.Command, name string, target wire.Addr, err error) (wire.Addr, error) {
	c := new(Conn)
	_, err = d.newConn(&ctx, c, op, "tcp", cmd, target, err)
	if err == nil {
		var conn net.Conn
		if conn, _, err = d.connect(ctx, c); err == nil {
			conn.Close()
			return c.h.bound, nil
		}
	}
	re, ok := errors.AsType[*ReplyError](err)
	e := &net.DNSError{Err: errors.Unwrap(err).Error(), Name: name, Server: d.server(), UnwrapErr: err,
		IsNotFound: ok && re.Reply == wire.ReplyHostUnreachable, IsTimeout: isTimeout(err)}
	if e.IsNotFound {
		e.Err = errNoSuchHost
	}
	e.IsTemporary = e.IsTimeout
	return wire.Addr{}, e
}

const errNoSuchHost = "no such host" // as net's

func (d *Dialer) notFound(name string) error {
	return &net.DNSError{Err: errNoSuchHost, Name: name, Server: d.server(), IsNotFound: true}
}

func (d *Dialer) server() string {
	if d == nil {
		return ""
	}
	return d.ProxyAddr
}
