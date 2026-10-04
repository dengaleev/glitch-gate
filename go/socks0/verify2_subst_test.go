package socks0_test

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestV2SubstitutionB1(t *testing.T) {
	if !hasIPv6() {
		t.Skip("no IPv6")
	}
	ips, _ := net.DefaultResolver.LookupNetIP(t.Context(), "ip", "localhost")
	if !slices.Contains(ips, netip.MustParseAddr("::1")) || !slices.Contains(ips, netip.MustParseAddr("127.0.0.1")) {
		t.Skip("localhost is not 127.0.0.1 and ::1")
	}
	t.Logf("localhost = %v", ips)
	unspec4 := func(ap netip.AddrPort) wire.Addr {
		return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port()))
	}
	unspec6 := func(ap netip.AddrPort) wire.Addr {
		return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), ap.Port()))
	}
	chain := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, addr)
	}
	for _, tt := range []struct {
		name, relay, listen string
		bnd                 func(netip.AddrPort) wire.Addr
		chain, relayListen  bool
		wantNet, wantHost   string
	}{
		{"chained :: over IPv6 control", "udp6", "tcp6", unspec6, true, false, "udp6", "::1"},
		{"chained 0.0.0.0 over IPv6 control", "udp4", "tcp6", unspec4, true, false, "udp4", "127.0.0.1"},
		{"chained :: over IPv4 control", "udp4", "tcp4", unspec6, true, false, "udp4", "127.0.0.1"},
		{"direct :: over IPv4 control", "udp4", "tcp4", unspec6, false, false, "udp4", "127.0.0.1"},
		{"direct :: over IPv6 control", "udp6", "tcp6", unspec6, false, false, "udp6", "::1"},
		{"RelayListen chained 0.0.0.0 over IPv6 control", "udp4", "tcp6", unspec4, true, true, "udp4", "127.0.0.1"},
		{"RelayListen chained :: over IPv6 control", "udp6", "tcp6", unspec6, true, true, "udp6", "::1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			echoAP := udpServe(t, tt.relay, echo)
			addr := listenOn(t, tt.listen, udpProxy{network: tt.relay, bnd: tt.bnd}.serve)
			_, port, _ := net.SplitHostPort(addr)
			var dialed []string
			d := &socks0.Dialer{
				ProxyAddr: net.JoinHostPort("localhost", port),
				Config: &socks0.Config{Trace: &socks0.ClientTrace{
					RelayDialStart: func(network, addr string) { dialed = append(dialed, network, addr) },
				}},
			}
			if tt.chain {
				d.ProxyDial = func(ctx context.Context, network, a string) (net.Conn, error) {
					// dial the listener's family explicitly
					return chain(ctx, cmp.Or(map[string]string{"tcp6": "tcp6", "tcp4": "tcp4"}[tt.listen], network), a)
				}
			} else {
				// direct: the dialer must reach the right family; force it
				d.ProxyDial = nil
				if tt.listen == "tcp6" {
					d.ProxyAddr = net.JoinHostPort("localhost", port)
				}
			}
			if tt.relayListen {
				d.RelayListen = new(net.ListenConfig).ListenPacket
			}
			c, err := d.DialContext(t.Context(), "udp", echoAP.String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			uc := c.(*socks0.UDPConn)
			want := []string{tt.wantNet, net.JoinHostPort(tt.wantHost, fmt.Sprint(uc.BoundAddr().Port()))}
			if !slices.Equal(dialed, want) {
				t.Errorf("relay dialed %q, want %q", dialed, want)
			}
			if s := roundTrip(t, c, "hi"); s != "hi" {
				t.Errorf("echo %q", s)
			}
		})
	}
}
