//go:build !linux

package socks0

import (
	"context"
	"net"
)

const FastOpenSupported = false

// FastOpenDial returns a Dialer.ProxyDial dialing like d (nil: zero) with TCP
// Fast Open (Linux TCP_FASTOPEN_CONNECT); no fallback, and elsewhere every
// call fails matching errors.ErrUnsupported. ConnectDone(nil) no longer
// proves reachability, so never use it for probes. Security: SYN data may be
// replayed (RFC 7413 §6): a duplicate CONNECT and, in ModeEarly, early data.
func FastOpenDial(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errFastOpen}
	}
}

func firstWrite(conn net.Conn, b []byte) (int, error) { return conn.Write(b) }
