package server

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// BindHandler serves BIND: it listens, sends the first reply, accepts until a conn comes from the
// expected peer, then sends the second reply and relays.
//
// The expected peer is DST's IP, any port. A name DST matches any of its IPs Filter allows (else
// 04 before listening, so internal names look unknown); a denied IP gets 02; an unspecified DST
// accepts the first allowed peer. Other peers are closed. Client bytes sent while waiting are
// buffered (≤ 2 KiB) to notice it closing. Each BIND holds a port, a goroutine and the conn for
// up to AcceptTimeout: on a public server set MaxConns and limit BINDs in Server.Allow.
type BindHandler struct {
	// Listen defaults to "tcp" on r.LocalAddr's IP, port 0.
	Listen func(ctx context.Context, network, address string) (net.Listener, error)

	// Advertise is as for AssociateHandler.
	Advertise func(r *Request, ln netip.AddrPort) wire.Addr

	// Filter vets each connecting peer (nil: DefaultFilter); a denied one is closed.
	Filter Filter

	AcceptTimeout time.Duration // zero means 2 min, negative none; expiry is replied 06
	Relayer       Relayer
}

// ServeSOCKS replies 07 to other commands.
func (h *BindHandler) ServeSOCKS(ctx context.Context, r *Request) error {
	if r.Command != wire.CmdBind {
		return notSupported(r)
	}
	want, err := h.expectedPeers(ctx, r)
	if err != nil {
		return err
	}
	listen := h.Listen
	if listen == nil {
		listen = new(net.ListenConfig).Listen
	}
	ln, err := listen(ctx, "tcp", hostPort(ipOf(r.LocalAddr), 0))
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := r.ReplyListening(advertised(h.Advertise, r, addrPortOf(ln.Addr()))); err != nil {
		return err
	}
	peer, err := h.accept(ctx, r, ln, want)
	if err != nil {
		return err
	}
	ln.Close()
	c, err := r.Reply(wire.ReplySucceeded, wire.AddrFromAddrPort(addrPortOf(peer.RemoteAddr())))
	if err != nil {
		peer.Close()
		return err
	}
	_, _, err = h.Relayer.Relay(ctx, c, peer)
	return err
}

// expectedPeers returns nil for any; unresolvable and all-denied names get the same error (L6).
func (h *BindHandler) expectedPeers(ctx context.Context, r *Request) ([]netip.Addr, error) {
	dst := r.Addr
	if !dst.IsName() {
		ip := dst.IP().Unmap().WithZone("")
		if ip.IsUnspecified() {
			return nil, nil
		}
		if err := h.Filter.allow(r, ipNetwork(ip), netip.AddrPortFrom(ip, 0)); err != nil {
			return nil, err
		}
		return []netip.Addr{ip}, nil
	}
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", dst.Name())
	var want []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		if h.Filter.allow(r, ipNetwork(ip), netip.AddrPortFrom(ip, 0)) == nil {
			want = append(want, ip)
		}
	}
	if len(want) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: dst.Name(), IsNotFound: true}
	}
	return want, nil
}

const defaultAcceptTimeout = 2 * time.Minute

func (h *BindHandler) accept(ctx context.Context, r *Request, ln net.Listener, want []netip.Addr) (net.Conn, error) {
	if t := cmp.Or(h.AcceptTimeout, defaultAcceptTimeout); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	gone := make(chan struct{})
	stopWatch := r.sc.watchClient(func() { close(gone); ln.Close() })
	defer stopWatch()
	defer context.AfterFunc(ctx, func() { ln.Close() })()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-gone:
				return nil, errClientGone
			default:
			}
			return nil, cmp.Or(ctx.Err(), err)
		}
		peer := addrPortOf(c.RemoteAddr())
		if want != nil && !slices.Contains(want, peer.Addr()) ||
			h.Filter.allow(r, tcpNetwork(peer.Addr()), peer) != nil {
			c.Close()
			continue
		}
		return c, nil
	}
}

// watchClient buffers the client's bytes before any reply to notice it closing; they stay in
// front of the Conn (I3) and a FIN is kept (I6).
func (sc *serverConn) watchClient(gone func()) (stop func()) {
	var wg sync.WaitGroup
	wg.Go(func() { sc.readUntilGone(gone) })
	return func() {
		_ = sc.nc.SetReadDeadline(aLongTimeAgo)
		wg.Wait()
		_ = sc.nc.SetReadDeadline(time.Time{})
	}
}

func (sc *serverConn) readUntilGone(gone func()) {
	for in := sc.bufp.in[:]; ; {
		if sc.w == len(in) {
			if sc.r == 0 {
				return
			}
			sc.w, sc.r = copy(in, in[sc.r:sc.w]), 0
		}
		n, err := sc.nc.Read(in[sc.w:])
		sc.w += n
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded):
			return
		default:
			sc.readErr = err
			gone()
			return
		}
	}
}
