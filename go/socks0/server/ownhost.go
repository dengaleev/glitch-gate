package server

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// The own-host check (S3) caches interface addresses for hostTTL, as a route lookup per dial costs
// a socket, four syscalls and ten allocations; it adds loopback, unspecified and NAT64/6to4-embedded
// addresses, which a route lookup misses. The route lookup is the fallback when listing fails.

// Vars for tests.
var (
	hostTTL        = time.Second
	interfaceAddrs = net.InterfaceAddrs
)

type hostAddrs struct {
	ips     map[netip.Addr]struct{} // unmapped, without zone; nil if the listing failed
	expires time.Time
}

var (
	hostMu          sync.Mutex // serializes listings
	cachedHostAddrs atomic.Pointer[hostAddrs]
)

// currentHostAddrs returns the stale listing while another goroutine refreshes it.
func currentHostAddrs() *hostAddrs {
	h := cachedHostAddrs.Load()
	if h != nil && time.Now().Before(h.expires) {
		return h
	}
	if !hostMu.TryLock() {
		if h != nil {
			return h
		}
		hostMu.Lock()
	}
	defer hostMu.Unlock()
	if h := cachedHostAddrs.Load(); h != nil && time.Now().Before(h.expires) {
		return h
	}
	h = listHostAddrs()
	cachedHostAddrs.Store(h)
	return h
}

func listHostAddrs() *hostAddrs {
	h := &hostAddrs{expires: time.Now().Add(hostTTL)} // counted from before the listing
	addrs, err := interfaceAddrs()
	if err != nil {
		return h
	}
	h.ips = make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch a := a.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if ip, ok := netip.AddrFromSlice(ip); ok {
			h.ips[ip.Unmap()] = struct{}{}
		}
	}
	return h
}

// ownHost falls back to the kernel's source address for dst (normalized), which equals dst for
// this host.
func ownHost(dst netip.AddrPort) netip.AddrPort {
	h := currentHostAddrs()
	if h.ips == nil {
		return sourceFor(dst)
	}
	ip := dst.Addr()
	for _, a := range [...]netip.Addr{ip, embedded4(ip)} {
		if !a.IsValid() {
			continue
		}
		if _, ok := h.ips[a]; ok || a.IsLoopback() || a.IsUnspecified() {
			return dst
		}
	}
	return netip.AddrPort{}
}

func sourceFor(dst netip.AddrPort) netip.AddrPort {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return netip.AddrPort{}
	}
	defer c.Close()
	return addrPortOf(c.LocalAddr())
}
