package server

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// Filter decides whether a built-in handler may reach addr (resolved, unmapped, zone-free) for r;
// network is tcp4/6, udp4/6, or ip4/6 (port meaningless) for a RESOLVE answer or a BIND peer. An
// error is replied as ReplyFor(err): 02 for a *DeniedError, 04 if a name was sent (no oracle).
// It must be pure (the UDP relay caches verdicts) and not panic (it runs on Happy Eyeballs goroutines).
type Filter func(r *Request, network string, addr netip.AddrPort) error

// DefaultFilter denies, with a *DeniedError, every address that is not globally reachable unicast:
//   - IPv4: 0/8, 10/8, 100.64/10, 127/8, 169.254/16 (incl. cloud metadata), 172.16/12, 192.0.0/24,
//     192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4,
//     and 168.63.129.16 (Azure WireServer).
//   - IPv6 outside 2000::/3, and 2001::/23, 2001:db8::/32, 3fff::/20 (so also fd00:ec2::254).
//   - IPv4-mapped, NAT64 64:ff9b::/96 and 6to4 2002::/16 addresses, by the IPv4 they embed.
//   - Port 0, except for network "ip4" and "ip6".
//   - The own host: r.LocalAddr's IP and Server.SelfAddrs, and, asked again before each TCP
//     connect and new UDP target, any other address of this host (interfaces, loopback,
//     unspecified), before a packet is sent: open and closed ports get the same reply.
//
// NAT64 network-specific prefixes (464XLAT) look global: wrap DefaultFilter to judge them by the
// IPv4 they embed. Chained proxies need their own Filter or Allow against loops.
func DefaultFilter(r *Request, network string, addr netip.AddrPort) error {
	addr = normalize(addr)
	var reason string
	switch {
	case r != nil && r.isSelf(addr.Addr()):
		reason = "own address"
	case addr.Port() == 0 && !strings.HasPrefix(network, "ip"):
		reason = "port 0"
	default:
		if reason = classify(addr.Addr()); reason == "" {
			return nil
		}
	}
	return &DeniedError{Addr: addr, Reason: reason}
}

func AllowAll(*Request, string, netip.AddrPort) error { return nil }

// Control returns a net.Dialer.ControlContext for custom Dial funcs, applying f (nil: DefaultFilter)
// and the own-host check to every address tried.
func (f Filter) Control(r *Request) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, network, address string, _ syscall.RawConn) error {
		return f.checkDial(r, network, address)
	}
}

// checkDial runs before connecting: no packet reaches this host's services, so no port-scan oracle.
func (f Filter) checkDial(r *Request, network, address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &DeniedError{Reason: "unparsable address"}
	}
	if err := f.allow(r, network, ap); err != nil {
		return err
	}
	return f.checkOwnHost(r, network, ownHost(ap), ap, nil)
}

func (f Filter) allow(r *Request, network string, ap netip.AddrPort) error {
	if f == nil {
		f = DefaultFilter
	}
	return f(r, network, normalize(ap))
}

// checkOwnHost asks f again with LocalAddr set to remote if remote is this host. Under Happy
// Eyeballs it runs concurrently: one call uses the conn's scratch, others allocate.
func (f Filter) checkOwnHost(r *Request, network string, local, remote netip.AddrPort, remoteAddr net.Addr) error {
	if !local.IsValid() || normalize(local).Addr() != normalize(remote).Addr() {
		return nil
	}
	remote = normalize(remote)
	var rr *Request
	if r != nil && r.sc != nil && r.sc.scratch.busy.CompareAndSwap(false, true) {
		scr := &r.sc.scratch
		defer scr.busy.Store(false)
		rr = &scr.req
		if remoteAddr == nil {
			n := copy(scr.ip[:], remote.Addr().AsSlice())
			scr.addr = net.TCPAddr{IP: scr.ip[:n:n], Port: int(remote.Port())}
			remoteAddr = &scr.addr
		}
	} else {
		rr = new(Request)
	}
	if remoteAddr == nil {
		remoteAddr = net.TCPAddrFromAddrPort(remote)
	}
	if r != nil {
		*rr = *r
	}
	rr.LocalAddr = remoteAddr
	return f.allow(rr, network, remote)
}

func (r *Request) isSelf(ip netip.Addr) bool {
	local := ipOf(r.LocalAddr)
	var self []netip.Prefix
	if r.sc != nil {
		self = r.sc.s.cfg.selfAddrs
	}
	for _, a := range [...]netip.Addr{ip, embedded4(ip)} {
		if !a.IsValid() {
			continue
		}
		if a == local {
			return true
		}
		for _, p := range self {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

func normalize(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

func ipOf(a net.Addr) netip.Addr {
	return addrPortOf(a).Addr()
}

func addrPortOf(a net.Addr) netip.AddrPort {
	switch a := a.(type) {
	case *net.TCPAddr:
		return normalize(a.AddrPort())
	case *net.UDPAddr:
		return normalize(a.AddrPort())
	case nil:
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return normalize(ap)
}

type prefixReason struct {
	p      netip.Prefix
	reason string
}

func pfx(s, reason string) prefixReason { return prefixReason{netip.MustParsePrefix(s), reason} }

var (
	denied4 = []prefixReason{
		pfx("0.0.0.0/8", "unspecified"),
		pfx("10.0.0.0/8", "private"),
		pfx("100.64.0.0/10", "cgnat"),
		pfx("127.0.0.0/8", "loopback"),
		pfx("169.254.0.0/16", "link-local"),
		pfx("172.16.0.0/12", "private"),
		pfx("192.0.0.0/24", "reserved"),
		pfx("192.0.2.0/24", "reserved"),
		pfx("192.88.99.0/24", "reserved"),
		pfx("168.63.129.16/32", "metadata"),
		pfx("192.168.0.0/16", "private"),
		pfx("198.18.0.0/15", "reserved"),
		pfx("198.51.100.0/24", "reserved"),
		pfx("203.0.113.0/24", "reserved"),
		pfx("224.0.0.0/4", "multicast"),
		pfx("240.0.0.0/4", "reserved"),
	}
	global6 = netip.MustParsePrefix("2000::/3")
	denied6 = []prefixReason{ // inside global6
		pfx("2001::/23", "reserved"),
		pfx("2001:db8::/32", "reserved"),
		pfx("3fff::/20", "reserved"),
	}
	other6 = []prefixReason{ // outside global6, for the reason only
		pfx("::/128", "unspecified"),
		pfx("::1/128", "loopback"),
		pfx("fc00::/7", "private"),
		pfx("fe80::/10", "link-local"),
		pfx("ff00::/8", "multicast"),
	}
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

func classify(ip netip.Addr) string {
	if ip.Is6() {
		switch v4 := embedded4(ip); {
		case v4.IsValid():
			ip = v4
		case !global6.Contains(ip):
			return reasonIn(other6, ip, "reserved")
		default:
			return reasonIn(denied6, ip, "")
		}
	}
	if !ip.Is4() {
		return "invalid"
	}
	return reasonIn(denied4, ip, "")
}

func embedded4(ip netip.Addr) netip.Addr {
	b := ip.As16()
	switch {
	case !ip.Is6():
	case nat64.Contains(ip):
		return netip.AddrFrom4([4]byte(b[12:]))
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte(b[2:6]))
	}
	return netip.Addr{}
}

func reasonIn(ps []prefixReason, ip netip.Addr, otherwise string) string {
	for _, p := range ps {
		if p.p.Contains(ip) {
			return p.reason
		}
	}
	return otherwise
}
