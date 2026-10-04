package socks0

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0/internal/sockopt"
)

var (
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

func scope(ip netip.Addr) int {
	switch {
	case ip.IsLoopback(), ip.IsUnspecified():
		return 0
	case ip.IsLinkLocalUnicast():
		return 1
	case ip.IsPrivate(), cgnat.Contains(ip):
		return 2
	}
	return 3
}

var scopeNames = [...]string{"loopback", "link-local", "private"}

// relayError's string holds no address.
type relayError struct{ why string }

func (e *relayError) Error() string { return "socks0: relay address refused: " + e.why }

func (e *relayError) Is(target error) bool { return target == ErrNotAllowed }

// checkRelay is the relay address policy against a hostile BND (see UDPConn).
func checkRelay(relay, proxy netip.Addr) error {
	relay, proxy = relay.Unmap().WithZone(""), proxy.Unmap().WithZone("")
	switch {
	case relay == proxy:
		return nil
	case relay.IsMulticast():
		return &relayError{"multicast"}
	case relay == broadcast4:
		return &relayError{"broadcast"}
	case relay.IsUnspecified():
		return &relayError{"unspecified"}
	}
	proxyScope := 3
	if proxy.IsValid() {
		proxyScope = scope(proxy)
	}
	if s := scope(relay); s < proxyScope {
		return &relayError{scopeNames[s] + " but the proxy is not (see Dialer.RelayUseProxyHost)"}
	}
	return nil
}

// proxyHost is ProxyAddr's host and, for a literal (even zoned), its IP,
// unmapped and zone-free as BND substitution and the relay policy use it.
type proxyHost struct {
	name string
	ip   netip.Addr
	err  error // ProxyAddr is not host:port
}

func (d *Dialer) proxyHost() proxyHost {
	host, _, err := net.SplitHostPort(d.ProxyAddr)
	var ip netip.Addr
	if strings.Contains(host, ":") || strings.Trim(host, "0123456789.") == "" {
		ip, _ = netip.ParseAddr(host) // not for a name: its error allocates
	}
	return proxyHost{host, ip.Unmap().WithZone(""), err}
}

// relayControl checks the dialed (so also resolved) address and clears
// SO_BROADCAST.
func relayControl(proxy netip.Addr) func(context.Context, string, string, syscall.RawConn) error {
	return func(_ context.Context, _, address string, c syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return &relayError{"unparsable"}
		}
		if err := checkRelay(ap.Addr(), proxy); err != nil {
			return err
		}
		return sockopt.NoBroadcast(c)
	}
}
