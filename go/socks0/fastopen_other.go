//go:build !linux

package socks0

import (
	"context"
	"net"
)

const FastOpenSupported = false

func fastOpenDial(*net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errFastOpen}
	}
}

func firstWrite(conn net.Conn, b []byte) (int, error) { return conn.Write(b) }
