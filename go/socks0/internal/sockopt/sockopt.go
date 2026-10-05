// Package sockopt holds the socket options shared by socks0 and its server.
package sockopt

import (
	"context"
	"net"
	"syscall"
)

// ListenNoBroadcast is net.ListenConfig.ListenPacket with SO_BROADCAST
// cleared, so a hostile peer cannot steer datagrams to a broadcast address.
func ListenNoBroadcast(ctx context.Context, network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error { return NoBroadcast(c) }}
	return lc.ListenPacket(ctx, network, address)
}
