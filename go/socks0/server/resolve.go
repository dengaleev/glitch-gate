package server

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// ResolveHandler serves Tor RESOLVE (F0) and RESOLVE_PTR (F1), closing the conn after the reply.
type ResolveHandler struct {
	// Resolver defaults to net.DefaultResolver; F1 needs a LookupAddr method, else it replies 07.
	Resolver socks0.Resolver

	// Filter decides which results may be disclosed: F0 answers the first allowed address, F1
	// refuses denied IPs (02). nil means DefaultFilter, so internal names look not found (04).
	Filter Filter
}

type ptrResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// ServeSOCKS replies 07 to other commands.
func (h *ResolveHandler) ServeSOCKS(ctx context.Context, r *Request) error {
	var res socks0.Resolver = net.DefaultResolver
	if h.Resolver != nil {
		res = h.Resolver
	}
	var bound wire.Addr
	var err error
	switch r.Command { // neither is a SOCKS4 command
	case wire.CmdTorResolve:
		bound, err = h.resolve(ctx, r, res)
	case wire.CmdTorResolvePTR:
		bound, err = h.resolvePTR(ctx, r, res)
	default:
		return notSupported(r)
	}
	if err != nil {
		return err
	}
	c, err := r.Reply(wire.ReplySucceeded, bound)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

func (h *ResolveHandler) resolve(ctx context.Context, r *Request, res socks0.Resolver) (wire.Addr, error) {
	if ip := r.Addr.IP(); ip.IsValid() {
		return wire.AddrFromAddrPort(netip.AddrPortFrom(ip, 0)), h.Filter.allowIP(r, ip)
	}
	var one [1]netip.Addr
	ips, _, err := h.Filter.lookupAllowed(ctx, res, r, r.Addr.Name(), 0, ipNetwork, one[:0])
	switch {
	case err != nil:
		return wire.Addr{}, err
	case len(ips) == 0: // denied names look unknown
		return wire.Addr{}, notFound(r.Addr.Name())
	}
	return wire.AddrFromAddrPort(netip.AddrPortFrom(ips[0], 0)), nil
}

func (h *ResolveHandler) resolvePTR(ctx context.Context, r *Request, res socks0.Resolver) (wire.Addr, error) {
	ip := r.Addr.IP()
	if !ip.IsValid() {
		return wire.Addr{}, &net.DNSError{Err: "unrecognized address", Name: r.Addr.Name()}
	}
	if err := h.Filter.allowIP(r, ip); err != nil {
		return wire.Addr{}, err
	}
	ptr, ok := res.(ptrResolver)
	if !ok {
		return wire.Addr{}, errUnsupported
	}
	names, err := ptr.LookupAddr(ctx, ip.String())
	if err != nil {
		return wire.Addr{}, err
	}
	if len(names) == 0 {
		return wire.Addr{}, notFound(ip.String())
	}
	return wire.ParseAddr(net.JoinHostPort(strings.TrimSuffix(names[0], "."), "0"))
}

func ipNetwork(ip netip.Addr) string {
	if ip.Is4() {
		return "ip4"
	}
	return "ip6"
}
