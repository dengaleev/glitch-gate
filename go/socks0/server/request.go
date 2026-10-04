package server

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type Handler interface {
	// ServeSOCKS answers through r.Reply; if it returns without replying, the server replies
	// ReplyFor(err), never success (and ServeConn returns ErrNoReply for nil). On return the conn is
	// closed and r is invalid. ctx is canceled by Close and on return, not on client disconnect.
	// Panics are recovered, logged and replied 01 if no reply went out.
	ServeSOCKS(ctx context.Context, r *Request) error
}

type HandlerFunc func(ctx context.Context, r *Request) error

func (f HandlerFunc) ServeSOCKS(ctx context.Context, r *Request) error { return f(ctx, r) }

// Request methods belong to the handler's goroutine; Reply may run elsewhere, not during Peek.
type Request struct {
	Version    Version      // V4 or V5
	Command    wire.Command // SOCKS4: CmdConnect or CmdBind
	Addr       wire.Addr    // DST as sent; names unresolved (SOCKS4a too)
	Method     wire.Method  // selected; SOCKS4: MethodNoAuth, or MethodUserPass if Server.UserID admitted it
	Identity   any          // from the Authenticator or UserID
	LocalAddr  net.Addr     // the server address the client conn reached
	RemoteAddr net.Addr     // the client's

	sc *serverConn
}

// Early returns the bytes after the request already buffered, without reading or consuming them.
// The slice aliases the conn's buffer until Reply or Peek; kept longer it may show this conn's
// later bytes, never another conn's. L0/L1 clients send nothing before the reply.
func (r *Request) Early() []byte {
	sc := r.sc
	if !sc.lockLive() {
		return nil
	}
	defer sc.mu.Unlock()
	b := sc.bufp.in[sc.r:sc.w:sc.w]
	sc.exposed = sc.exposed || len(b) > 0
	return b
}

// Peek reads until n bytes after the request are buffered (n ≤ 2 KiB, else bufio.ErrBufferFull),
// EOF, ctx or the handshake deadline, and returns what Early would, with the error if fewer than n.
// It may invalidate earlier Early and Peek results. It suits only L2 clients.
func (r *Request) Peek(ctx context.Context, n int) ([]byte, error) {
	sc := r.sc
	if !sc.lockLive() {
		return nil, ErrReplied
	}
	sc.mu.Unlock()
	var err error
	if n = max(n, 0); n > inSize {
		n, err = inSize, bufio.ErrBufferFull
	}
	if sc.w-sc.r < n {
		if ferr := sc.fillCtx(ctx, n); ferr != nil {
			err = ferr
		}
	}
	end := min(sc.w, sc.r+n)
	if end > sc.r {
		sc.mu.Lock()
		sc.exposed = true
		sc.mu.Unlock()
	}
	return sc.bufp.in[sc.r:end:end], err
}

// lockLive locks mu unless a final reply went out or ServeSOCKS returned (or sc is nil); before
// either, the conn holds its buffer.
func (sc *serverConn) lockLive() bool {
	if sc == nil {
		return false
	}
	sc.mu.Lock()
	if sc.replied || sc.done || sc.bufp == nil {
		sc.mu.Unlock()
		return false
	}
	return true
}

// fillCtx: a timeout loses no bytes, so it is not sticky.
func (sc *serverConn) fillCtx(ctx context.Context, n int) error {
	_ = sc.nc.SetReadDeadline(sc.deadline)
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = sc.nc.SetReadDeadline(aLongTimeAgo)
		close(fired)
	})
	err := sc.fill(n)
	if !stop() {
		<-fired
	}
	_ = sc.nc.SetReadDeadline(time.Time{})
	if errors.Is(err, os.ErrDeadlineExceeded) {
		sc.readErr = nil
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}
	return err
}

// Reply sends the reply after any queued handshake bytes, bounded by HandshakeTimeout; a zero bound
// is sent as 0.0.0.0:0. On success it returns the conn with every byte read past the request in
// front of it and its deadlines cleared. Any other rep half-closes the conn (lingering close) and
// returns a *socks0.ReplyError; a write error closes it. conn != nil iff err == nil. SOCKS4 maps
// success to 0x5A, keeps 0x5A–0x5D and sends anything else as 0x5B. Later calls return ErrReplied.
func (r *Request) Reply(rep wire.Reply, bound wire.Addr) (*Conn, error) {
	sc := r.sc
	if !sc.lockLive() {
		return nil, ErrReplied
	}
	sc.replied = true
	err := sc.writeReply(rep, bound)
	ok := err == nil && isSuccess(rep)
	sc.mu.Unlock()
	sc.s.Trace.replied(sc.ctx, rep, bound, err)
	switch {
	case err != nil:
		sc.nc.Close()
		return nil, err
	case !ok:
		if cw, ok := sc.nc.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		v := uint8(5)
		if r.Version == V4 {
			v = 4
		}
		return nil, &socks0.ReplyError{Reply: rep, Bound: bound, Version: v}
	}
	_ = sc.nc.SetDeadline(time.Time{})
	sc.state.Store(uint32(StateTunnel))
	sc.s.setState(sc.nc, StateTunnel)
	return &sc.conn, nil
}

var errNotBind = errors.New("socks0/server: ReplyListening: not a BIND request")

// ReplyListening sends BIND's first reply (success, bound where the server listens); Reply then
// sends the second. Only for CmdBind; ErrReplied if called twice or after Reply.
func (r *Request) ReplyListening(bound wire.Addr) error {
	sc := r.sc
	switch {
	case sc == nil:
		return ErrReplied
	case r.Command != wire.CmdBind:
		return errNotBind
	case !sc.lockLive():
		return ErrReplied
	case sc.listening:
		sc.mu.Unlock()
		return ErrReplied
	}
	err := sc.writeReply(wire.ReplySucceeded, bound)
	sc.listening = err == nil
	sc.replied = err != nil
	sc.mu.Unlock()
	sc.s.Trace.replied(sc.ctx, wire.ReplySucceeded, bound, err)
	if err != nil {
		sc.nc.Close()
		return err
	}
	_ = sc.nc.SetWriteDeadline(time.Time{})
	return nil
}
