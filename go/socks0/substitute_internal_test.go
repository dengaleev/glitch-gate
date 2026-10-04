package socks0

import (
	"net/netip"
	"testing"
)

func TestPickRelayIP(t *testing.T) {
	ip := netip.MustParseAddr
	v4, v6 := netip.IPv4Unspecified(), netip.IPv6Unspecified()
	for _, tc := range []struct {
		name  string
		ips   []string
		peer  string
		bound netip.Addr
		want  string
	}{
		{"peer v4, BND 0.0.0.0", []string{"::1", "127.0.0.1"}, "127.0.0.1", v4, "127.0.0.1"},
		{"peer v6, BND 0.0.0.0: first IPv4", []string{"::1", "127.0.0.1"}, "::1", v4, "127.0.0.1"},
		{"peer v4, BND ::: peer", []string{"::1", "127.0.0.1"}, "127.0.0.1", v6, "127.0.0.1"},
		{"peer v6 mapped, BND ::", []string{"::ffff:127.0.0.1", "::1"}, "127.0.0.1", v6, "127.0.0.1"},
		{"peer absent, BND ::: first IPv6", []string{"127.0.0.1", "::1"}, "127.0.0.2", v6, "::1"},
		{"peer absent, BND 0.0.0.0: first IPv4", []string{"::1", "127.0.0.1"}, "", v4, "127.0.0.1"},
		{"no IPv6, BND ::: first", []string{"127.0.0.1", "127.0.0.3"}, "127.0.0.2", v6, "127.0.0.1"},
		{"no IPv4, BND 0.0.0.0: first", []string{"::1", "::2"}, "", v4, "::1"},
	} {
		var ips []netip.Addr
		for _, s := range tc.ips {
			ips = append(ips, ip(s))
		}
		var peer netip.Addr
		if tc.peer != "" {
			peer = ip(tc.peer)
		}
		if got := pickRelayIP(ips, peer, tc.bound); got != ip(tc.want) {
			t.Errorf("%s: %v, want %s", tc.name, got, tc.want)
		}
	}
}
