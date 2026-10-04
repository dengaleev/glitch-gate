package socks0

import (
	"context"
	"net"
	"net/netip"
	"syscall"
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

func (d *Dialer) proxyIP(control net.Conn) netip.Addr {
	if host, _, err := net.SplitHostPort(d.ProxyAddr); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip
		}
	}
	if ta, ok := control.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr()
	}
	return netip.Addr{}
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
		return noBroadcast(c)
	}
}

func listenNoBroadcast(ctx context.Context, network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error { return noBroadcast(c) }}
	return lc.ListenPacket(ctx, network, address)
}
