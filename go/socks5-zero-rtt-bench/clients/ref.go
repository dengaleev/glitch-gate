package clients

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/internal/s5"
)

// refL1 writes the whole handshake at once, then reads all replies: 1 RTT.
func refL1(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	c, hs, err := dialProxy(ctx, addr, user, pass, target)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	if _, err = c.Write(hs); err == nil {
		err = s5.ReadReplies(c, user)
	}
	if !stop() { // ctx closed c
		err = ctx.Err()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// refL1L2 sends the handshake with the first write: SOCKS adds no RTT.
func refL1L2(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	c, hs, err := dialProxy(ctx, addr, user, pass, target)
	if err != nil {
		return nil, err
	}
	return &earlyConn{Conn: c, user: user, hs: hs, replied: make(chan struct{})}, nil
}

// dialProxy connects to the proxy and encodes the pipelined handshake.
func dialProxy(ctx context.Context, addr, user, pass, target string) (net.Conn, []byte, error) {
	hs, err := s5.Handshake(user, pass, target)
	if err != nil {
		return nil, nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	return c, hs, err
}

// earlyConn prepends the handshake to the first Write (or sends it alone if
// Read comes first) and consumes the replies on the first Read. Write never
// waits for them, and holds no lock, so a huge first Write can't block the
// reader. A failed handshake surfaces from Read, and from Write once known.
// Safe for one reader and one writer.
type earlyConn struct {
	net.Conn
	user string
	hs   []byte

	handshakeSent atomic.Bool

	readOnce sync.Once
	replied  chan struct{} // closed once replyErr is set
	replyErr error
}

func (c *earlyConn) Write(p []byte) (int, error) {
	if c.handshakeSent.CompareAndSwap(false, true) {
		n, err := c.Conn.Write(append(c.hs, p...))
		return max(n-len(c.hs), 0), err
	}
	select {
	case <-c.replied:
		if c.replyErr != nil {
			return 0, c.replyErr
		}
	default:
	}
	return c.Conn.Write(p)
}

func (c *earlyConn) Read(p []byte) (int, error) {
	if c.handshakeSent.CompareAndSwap(false, true) {
		if _, err := c.Conn.Write(c.hs); err != nil {
			return 0, err
		}
	}
	c.readOnce.Do(func() {
		c.replyErr = s5.ReadReplies(c.Conn, c.user)
		close(c.replied)
	})
	if c.replyErr != nil {
		return 0, c.replyErr
	}
	return c.Conn.Read(p)
}
