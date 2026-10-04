package socks0

import (
	"context"
	"net"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Request runs the handshake for cmd over conn (ModeEarly as ModePipelined),
// reading nothing past the first reply, and returns its BND. conn is never
// closed; if ctx fires its deadline is left in the past. Errors are
// *net.OpError wrapping a *HandshakeError; a BND cmd cannot use is a
// *ProtocolError.
func Request(ctx context.Context, conn net.Conn, cmd wire.Command, addr wire.Addr, cfg *Config) (bound wire.Addr, err error) {
	c := &Conn{conn: conn, network: "tcp", op: opOf(cmd)}
	c.h.target = addr
	if conn == nil {
		return wire.Addr{}, c.opError(&HandshakeError{StageConfig, errNoConn})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.init(cfg, cmd, addr); err != nil {
		return wire.Addr{}, c.opError(&HandshakeError{StageConfig, err})
	}
	c.trace = newTracer(ctx, c.configTrace)
	if err := c.handshakeOver(ctx, conn, false, time.Time{}); err != nil {
		return wire.Addr{}, err
	}
	return c.h.bound, nil
}
