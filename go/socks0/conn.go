package socks0

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	_ net.Conn      = (*Conn)(nil)
	_ io.ReaderFrom = (*Conn)(nil)
	_ io.WriterTo   = (*Conn)(nil)
	_ syscall.Conn  = (*Conn)(nil)
)

const maxEarlyData = 32 << 10

// Conn is a connection through a SOCKS proxy (Client, ClientAddr, a ModeEarly
// Dialer, Listener.Accept). The first HandshakeContext, Read, Write, ReadFrom,
// WriteTo or CloseWrite runs the handshake (implicitly with
// context.Background, bounded by deadlines and Config.HandshakeTimeout).
// In ModeEarly the first Write sends the handshake plus up to 32 KiB of data;
// a Read before it waits for a Write, HandshakeContext, CloseWrite, Close or
// the read deadline. Write never waits for the replies.
// Handshake errors (*net.OpError{Op: "socks connect"} wrapping a
// *HandshakeError) are sticky; the conn stays open until Close. Safe for one
// reader and one writer, plus HandshakeContext, CloseWrite, Close and the
// deadline setters from any goroutine. The zero Conn returns errors.
type Conn struct {
	conn             net.Conn
	h                handshake
	op               string    // of handshake errors; "" is "socks connect"
	network          string    // of errors
	proxy            wire.Addr // Source of errors; the conn's RemoteAddr if invalid
	laddr, raddr     net.Addr  // Listener.Accept's
	replyTimeout     time.Duration
	handshakeTimeout time.Duration
	configTrace      *ClientTrace
	doneAfterRelay   bool // a successful UDP ASSOCIATE's HandshakeDone is the caller's

	// Fast paths that skip mu.
	readReady  atomic.Bool // replies consumed
	writeReady atomic.Bool // handshake written without error
	isShut     atomic.Bool // closed

	mu            sync.Mutex
	trace         tracer
	traceSet      bool
	claimed       bool // a call is sending, or has sent, the handshake
	written       bool // its write is over
	busy          bool // a call is reading the replies or running the handshake
	done          bool // err or bound is set
	closed        bool
	abortErr      error // cancellation or Close, to fail the handshake with
	err           error // sticky
	bound         wire.Addr
	readDeadline  time.Time // the caller's
	replyDeadline time.Time // ReplyTimeout of the call reading the replies
	wake          chan struct{}

	inline [128]byte
}

// Client returns a Conn that runs the handshake for target over conn (TCP,
// TLS, a mux stream). Names go to the proxy unresolved. Invalid arguments
// surface as the handshake error.
func Client(conn net.Conn, target string, cfg *Config) *Conn {
	a, err := wire.ParseAddr(target)
	c := ClientAddr(conn, a, cfg)
	if err != nil && c.conn != nil {
		c.err = c.opError(&HandshakeError{StageConfig, err})
	}
	return c
}

func ClientAddr(conn net.Conn, target wire.Addr, cfg *Config) *Conn {
	c := &Conn{conn: conn, network: "tcp"}
	c.h.target, c.h.mu, c.h.buf = target, &c.mu, c.inline[:0] // target for config errors too
	if conn == nil {
		c.err = c.opError(&HandshakeError{StageConfig, errNoConn})
		c.done = true
		return c
	}
	if err := c.init(cfg, wire.CmdConnect, target); err != nil {
		c.err = c.opError(&HandshakeError{StageConfig, err})
		c.done = true
	}
	return c
}

func (c *Conn) init(cfg *Config, cmd wire.Command, target wire.Addr) error {
	if cfg == nil {
		cfg = new(Config)
	}
	c.replyTimeout, c.handshakeTimeout, c.configTrace = cfg.ReplyTimeout, cfg.HandshakeTimeout, cfg.Trace
	if err := c.h.init(cfg, cmd); err != nil {
		return err
	}
	return c.h.setTarget(target)
}

// HandshakeContext runs the handshake if needed and waits for the replies.
// Cancelling ctx fails the handshake for good (wrapping ctx.Err()); a conn
// that cannot set deadlines is then closed, as crypto/tls does.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if c.readReady.Load() {
		return nil
	}
	if c.conn == nil {
		return c.noConn("socks connect")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		c.abortWith(err) // now, not later on AfterFunc's goroutine
	} else if ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() { c.abortWith(ctx.Err()) })
		defer stop()
	}
	return c.handshake(ctx, "socks connect", true)
}

func (c *Conn) handshake(ctx context.Context, op string, send bool) error {
	if c.h.mode != ModeEarly {
		return c.run(ctx, op)
	}
	if send {
		if err := c.sendAlone(ctx, op); err != nil {
			return err
		}
	}
	return c.awaitReplies(ctx, op)
}

// BoundAddr returns BND of a successful reply, else the zero Addr.
func (c *Conn) BoundAddr() wire.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bound
}

// NetConn returns the underlying conn; using it mid-handshake corrupts the
// stream. After an aborted handshake its deadlines may be in the past.
func (c *Conn) NetConn() net.Conn { return c.conn }

func (c *Conn) Read(b []byte) (int, error) {
	if !c.readReady.Load() {
		if c.conn == nil {
			return 0, c.noConn("read")
		}
		if err := c.handshake(context.Background(), "read", false); err != nil {
			return 0, err
		}
	}
	n, err := c.conn.Read(b)
	return n, c.ioErr("read", err)
}

// Write's count excludes handshake bytes.
func (c *Conn) Write(b []byte) (int, error) {
	if !c.writeReady.Load() {
		if c.conn == nil {
			return 0, c.noConn("write")
		}
		if c.h.mode == ModeEarly {
			return c.writeEarly(b)
		}
		if err := c.run(context.Background(), "write"); err != nil {
			return 0, err
		}
	}
	n, err := c.conn.Write(b)
	return n, c.ioErr("write", err)
}

func (c *Conn) writeEarly(b []byte) (int, error) {
	mustSend, err := c.claim(context.Background(), "write")
	if err != nil {
		return 0, err
	}
	if !mustSend {
		if err := c.waitWritten("write"); err != nil {
			return 0, err
		}
		n, err := c.conn.Write(b)
		return n, c.ioErr("write", err)
	}
	k := min(len(b), maxEarlyData)
	n, err := c.send(append(append(make([]byte, 0, len(c.h.out)+k), c.h.out...), b[:k]...))
	if err != nil || k == len(b) {
		return n, err
	}
	m, err := c.conn.Write(b[k:])
	return n + m, c.ioErr("write", err)
}

// ReadFrom does not wait for the replies, so sendfile and splice apply.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	var sent int64
	if !c.writeReady.Load() {
		if c.conn == nil {
			return 0, c.noConn("readfrom")
		}
		var done bool
		var err error
		if c.h.mode == ModeEarly {
			sent, done, err = c.readFromEarly(r)
		} else {
			err = c.run(context.Background(), "readfrom")
		}
		if err != nil || done {
			return sent, err
		}
	}
	n, err := io.Copy(c.conn, r)
	return sent + n, c.ioErr("readfrom", err)
}

func (c *Conn) readFromEarly(r io.Reader) (n int64, done bool, err error) {
	c.mu.Lock()
	err, claimed := c.checkLocked("readfrom"), c.claimed
	c.mu.Unlock()
	switch {
	case err != nil:
		return 0, true, err
	case claimed:
		return 0, false, c.waitWritten("readfrom")
	}
	hs := len(c.h.out)
	buf := append(make([]byte, 0, hs+maxEarlyData), c.h.out...)
	var m int
	var rerr error
	for m == 0 && rerr == nil {
		m, rerr = r.Read(buf[hs:cap(buf)])
	}
	eof := errors.Is(rerr, io.EOF)
	if m == 0 && !eof {
		return 0, true, rerr
	}
	mustSend, err := c.claim(context.Background(), "readfrom")
	if err != nil {
		return 0, true, err
	}
	var w int
	if mustSend {
		w, err = c.send(buf[:hs+m])
	} else {
		c.h.wipe(buf) // its copy of the handshake is not sent
		if err = c.waitWritten("readfrom"); err == nil {
			w, err = c.conn.Write(buf[hs : hs+m])
			err = c.ioErr("readfrom", err)
		}
	}
	if err == nil && !eof {
		err = rerr
	}
	return int64(w), err != nil || rerr != nil, err
}

// WriteTo waits for the replies; splice applies.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if !c.readReady.Load() {
		if c.conn == nil {
			return 0, c.noConn("writeto")
		}
		if err := c.handshake(context.Background(), "writeto", false); err != nil {
			return 0, err
		}
	}
	n, err := io.Copy(w, c.conn)
	return n, c.ioErr("writeto", err)
}

// CloseWrite waits for the replies, then half-closes; errors.ErrUnsupported
// if the underlying conn cannot.
func (c *Conn) CloseWrite() error {
	if c.conn == nil {
		return c.noConn("close")
	}
	c.mu.Lock()
	err := c.checkLocked("close")
	c.mu.Unlock()
	cw, ok := c.conn.(interface{ CloseWrite() error })
	switch {
	case err != nil:
		return err
	case !ok:
		return c.connErr("close", errors.ErrUnsupported)
	}
	if !c.readReady.Load() {
		if err := c.handshake(context.Background(), "close", true); err != nil {
			return err
		}
	}
	return c.ioErr("close", cw.CloseWrite())
}

// Close fails a pending handshake.
func (c *Conn) Close() error {
	if c.conn == nil {
		return c.noConn("close")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.connErr("close", net.ErrClosed)
	}
	c.closed = true
	c.isShut.Store(true)
	c.readReady.Store(false)
	c.writeReady.Store(false)
	if c.abortErr == nil && !c.done {
		c.abortErr = net.ErrClosed
	}
	c.settleUnlock()
	return c.conn.Close()
}

// LocalAddr is the Listener's Addr for a Conn from Listener.Accept.
func (c *Conn) LocalAddr() net.Addr {
	switch {
	case c.laddr != nil:
		return c.laddr
	case c.conn == nil:
		return nil
	}
	return c.conn.LocalAddr()
}

// RemoteAddr is the proxy (see BoundAddr), or the peer for Listener.Accept.
func (c *Conn) RemoteAddr() net.Addr {
	switch {
	case c.raddr != nil:
		return c.raddr
	case c.conn == nil:
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline: ReplyTimeout may narrow it while replies are awaited.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return c.noConn("set")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.broadcastLocked() // a Read waiting for the first Write
	if c.abortErr != nil && !c.done {
		return nil // keep the conn unblocked for the handshake to fail
	}
	if !c.replyDeadline.IsZero() {
		t = earliest(t, c.replyDeadline)
	}
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return c.noConn("set")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.abortErr != nil && !c.done {
		return nil
	}
	return c.conn.SetWriteDeadline(t)
}

// SyscallConn fails matching errors.ErrUnsupported if conn is not a syscall.Conn.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	if c.conn == nil {
		return nil, c.noConn("raw-conn")
	}
	sc, ok := c.conn.(syscall.Conn)
	if !ok {
		return nil, c.connErr("raw-conn", errors.ErrUnsupported)
	}
	return sc.SyscallConn()
}

func (c *Conn) run(ctx context.Context, op string) error {
	c.mu.Lock()
	if mustRun, err := c.claimRunLocked(op); !mustRun {
		c.mu.Unlock()
		return err
	}
	c.setTraceLocked(ctx)
	tr := c.trace
	c.mu.Unlock()

	wrote, he := c.runTimed(ctx, tr)

	c.mu.Lock()
	c.endIOLocked(ctx)
	c.finishLocked(c.blameAbortLocked(he))
	err, herr := c.checkLocked(op), c.err
	c.mu.Unlock()
	if wrote {
		tr.handshakeDone(herr)
	}
	return err
}

func (c *Conn) claimRunLocked(op string) (mustRun bool, err error) {
	for {
		if err := c.checkLocked(op); err != nil || c.done {
			return false, err
		}
		if c.abortErr != nil && !c.claimed { // canceled before anything was sent
			c.finishLocked(&HandshakeError{c.h.writeStage(0), c.abortErr})
			continue
		}
		if !c.claimed {
			break
		}
		c.waitLocked(time.Time{})
	}
	c.claimed, c.written, c.busy = true, true, true
	return true, nil
}

// runTimed uses a bare timer, not a timer ctx: a fifth of the allocations.
func (c *Conn) runTimed(ctx context.Context, tr tracer) (wrote bool, he *HandshakeError) {
	if t := c.handshakeWait(ctx); t > 0 {
		timer := time.AfterFunc(t, c.handshakeExpired)
		defer timer.Stop()
	}
	return c.h.run(ctx, c.conn, tr)
}

// endIOLocked catches a cancellation that raced the end of the I/O.
func (c *Conn) endIOLocked(ctx context.Context) {
	c.busy = false
	if c.abortErr == nil && ctx.Err() != nil {
		c.abortErr = ctx.Err()
	}
}

func (c *Conn) blameAbortLocked(he *HandshakeError) *HandshakeError {
	switch {
	case c.abortErr == nil:
	case he == nil:
		he = &HandshakeError{c.h.replyStage(), c.abortErr}
	case !isServerMsgErr(he.Err):
		he.Err = c.abortErr
	}
	return he
}

func (c *Conn) claim(ctx context.Context, op string) (mustSend bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(op); err != nil || c.claimed {
		return false, err
	}
	c.claimed = true
	c.setTraceLocked(ctx)
	c.broadcastLocked()
	return true, nil
}

func (c *Conn) sendAlone(ctx context.Context, op string) error {
	mustSend, err := c.claim(ctx, op)
	if mustSend {
		_, err = c.send(c.h.out)
	}
	return err
}

func (c *Conn) send(b []byte) (int, error) {
	n, werr := firstWrite(c.conn, b)
	c.h.wipe(b)
	hs := len(c.h.out)
	c.mu.Lock()
	c.written = true
	tr := c.trace
	if werr != nil && n < hs {
		cause := werr
		if c.abortErr != nil {
			cause = c.abortErr
		}
		he := &HandshakeError{c.h.writeStage(n), cause}
		hook := c.finishLocked(he)
		if c.err == nil { // the replies came first, yet the proxy lacks the request
			c.err = c.opError(he)
			c.readReady.Store(false)
			c.writeReady.Store(false)
		}
		err := c.err
		c.mu.Unlock()
		tr.wroteHandshake(werr)
		if hook {
			tr.handshakeDone(err)
		}
		return 0, err
	}
	if c.err == nil && !c.closed {
		c.writeReady.Store(true)
	}
	c.broadcastLocked()
	c.settleUnlock()
	tr.wroteHandshake(werr)
	return n - hs, c.ioErr("write", werr)
}

func (c *Conn) waitWritten(op string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for !c.written && !c.done && !c.closed {
		c.waitLocked(time.Time{})
	}
	return c.checkLocked(op)
}

func (c *Conn) awaitReplies(ctx context.Context, op string) error {
	c.mu.Lock()
	if err := c.waitClaimedLocked(op); err != nil {
		c.mu.Unlock()
		return err
	}
	var replyDeadline time.Time
	if t := c.replyWait(ctx); t > 0 {
		replyDeadline = time.Now().Add(t)
	}
	if mustRead, err := c.claimReadLocked(op); !mustRead {
		c.mu.Unlock()
		return err
	}
	c.setReplyDeadlineLocked(replyDeadline)
	tr := c.trace
	c.mu.Unlock()

	he := c.h.readReplies(c.conn, tr)

	c.mu.Lock()
	c.endIOLocked(ctx)
	c.clearReplyDeadlineLocked()
	hook := c.finishLocked(c.replyErrLocked(he, replyDeadline))
	err, herr := c.checkLocked(op), c.err
	c.mu.Unlock()
	if hook {
		tr.handshakeDone(herr)
	}
	return err
}

func (c *Conn) waitClaimedLocked(op string) error {
	for !c.claimed && !c.done && !c.closed {
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return c.connErr(op, os.ErrDeadlineExceeded)
		}
		c.waitLocked(c.readDeadline)
	}
	return nil
}

func (c *Conn) claimReadLocked(op string) (mustRead bool, err error) {
	for {
		if err := c.checkLocked(op); err != nil || c.done {
			return false, err
		}
		if c.abortErr != nil && c.written && !c.busy {
			c.settleUnlock()
			c.mu.Lock()
			continue
		}
		if c.abortErr == nil && !c.busy {
			break
		}
		c.waitLocked(time.Time{})
	}
	c.busy = true
	return true, nil
}

func (c *Conn) setReplyDeadlineLocked(t time.Time) {
	if c.replyDeadline = t; !t.IsZero() {
		c.conn.SetReadDeadline(earliest(c.readDeadline, t))
	}
}

func (c *Conn) clearReplyDeadlineLocked() {
	if !c.replyDeadline.IsZero() {
		c.replyDeadline = time.Time{}
		if c.abortErr == nil {
			c.conn.SetReadDeadline(c.readDeadline)
		}
	}
}

func (c *Conn) replyErrLocked(he *HandshakeError, t time.Time) *HandshakeError {
	switch {
	case c.abortErr != nil && he == nil:
		he = &HandshakeError{c.h.replyStage(), c.abortErr}
	case c.abortErr != nil && !isServerMsgErr(he.Err):
		he.Err = c.abortErr
	case he != nil && c.isReplyTimeout(he.Err, t):
		he.Err = os.ErrDeadlineExceeded
	}
	return he
}

// isReplyTimeout tells the reply deadline t from the caller's read deadline.
func (c *Conn) isReplyTimeout(err error, t time.Time) bool {
	return !t.IsZero() && isTimeout(err) && !time.Now().Before(t) &&
		(c.readDeadline.IsZero() || t.Before(c.readDeadline))
}

func (c *Conn) abortWith(err error) {
	c.mu.Lock()
	if c.done || c.abortErr != nil {
		c.mu.Unlock()
		return
	}
	c.abortErr = err
	unblock(c.conn)
	c.settleUnlock()
}

// settleUnlock fails an aborted handshake no call is working on, wakes
// waiters and unlocks c.mu.
func (c *Conn) settleUnlock() {
	hook := false
	if c.abortErr != nil && c.claimed && c.written && !c.busy {
		hook = c.finishLocked(&HandshakeError{c.h.readStage, c.abortErr})
	}
	c.broadcastLocked()
	tr, err := c.trace, c.err
	c.mu.Unlock()
	if hook {
		tr.handshakeDone(err)
	}
}

// finishLocked reports whether HandshakeDone must run.
func (c *Conn) finishLocked(he *HandshakeError) bool {
	if c.done {
		return false
	}
	c.done = true
	c.broadcastLocked()
	if he != nil {
		c.err = c.opError(he)
		c.writeReady.Store(false)
		// Unblock other calls' handshake I/O: they return c.err.
		if c.busy {
			c.conn.SetReadDeadline(time.Unix(1, 0))
		}
		if c.claimed && !c.written {
			c.conn.SetWriteDeadline(time.Unix(1, 0))
		}
		return c.claimed
	}
	c.bound = c.h.bound
	if !c.closed {
		c.readReady.Store(true)
		c.writeReady.Store(c.written)
	}
	return c.claimed
}

func (c *Conn) setTraceLocked(ctx context.Context) {
	if !c.traceSet {
		c.trace, c.traceSet = newTracer(ctx, c.configTrace), true
	}
}

func (c *Conn) checkLocked(op string) error {
	switch {
	case !c.closed:
		return c.err
	case op != "socks connect":
		return c.connErr(op, net.ErrClosed)
	case c.claimed:
		return c.opError(&HandshakeError{c.h.readStage, net.ErrClosed})
	}
	return c.opError(&HandshakeError{c.h.writeStage(0), net.ErrClosed})
}

// waitLocked releases c.mu until a state change or t (zero: none).
func (c *Conn) waitLocked(t time.Time) {
	if c.wake == nil {
		c.wake = make(chan struct{})
	}
	wake := c.wake
	c.mu.Unlock()
	if t.IsZero() {
		<-wake
	} else {
		timer := time.NewTimer(time.Until(t))
		select {
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
	c.mu.Lock()
}

func (c *Conn) broadcastLocked() {
	if c.wake != nil {
		close(c.wake)
		c.wake = nil
	}
}

func (c *Conn) opError(he *HandshakeError) error {
	e := &net.OpError{Op: cmp.Or(c.op, opConnect), Net: c.network, Err: he}
	if c.proxy.IsValid() {
		e.Source = c.proxy
	} else if c.conn != nil {
		e.Source = c.conn.RemoteAddr()
	}
	if c.h.target.IsValid() {
		e.Addr = c.h.target
	}
	return e
}

func (c *Conn) connErr(op string, err error) error {
	return &net.OpError{Op: op, Net: c.network, Source: c.conn.LocalAddr(), Addr: c.conn.RemoteAddr(), Err: err}
}

func (c *Conn) ioErr(op string, err error) error {
	if err != nil && c.isShut.Load() && !errors.Is(err, net.ErrClosed) {
		return c.connErr(op, net.ErrClosed)
	}
	return err
}

func (c *Conn) noConn(op string) error {
	if c.err != nil {
		return c.err
	}
	return &net.OpError{Op: op, Net: "tcp", Err: &HandshakeError{StageConfig, errNoConn}}
}

// defaultHandshakeTimeout is a var for tests.
var defaultHandshakeTimeout = 30 * time.Second

func handshakeCtx(ctx context.Context, t time.Duration) (_ context.Context, cancel context.CancelFunc) {
	if t == 0 {
		if hasDeadline(ctx) {
			return ctx, nil
		}
		t = defaultHandshakeTimeout
	}
	if t < 0 {
		return ctx, nil
	}
	return context.WithTimeout(ctx, t)
}

func (c *Conn) replyWait(ctx context.Context) time.Duration {
	if c.replyTimeout > 0 {
		return c.replyTimeout
	}
	return c.handshakeWait(ctx)
}

func (c *Conn) handshakeWait(ctx context.Context) time.Duration {
	switch t := c.handshakeTimeout; {
	case t > 0:
		return t
	case t < 0 || hasDeadline(ctx):
		return 0
	}
	return defaultHandshakeTimeout
}

func (c *Conn) handshakeExpired() { c.abortWith(context.DeadlineExceeded) }

func hasDeadline(ctx context.Context) bool {
	_, ok := ctx.Deadline()
	return ok
}

func earliest(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func (c *Conn) handshakeOver(ctx context.Context, conn net.Conn, tr tracer, closeOnErr func() error, dl time.Time) error {
	var stop func() bool
	if ctx.Done() != nil {
		stop = context.AfterFunc(ctx, func() { unblock(conn) })
	}
	wrote, he := c.h.run(ctx, conn, tr)
	fired := stop != nil && !stop()
	he = c.blameCtx(ctx, he, fired, dl)
	var err error
	if he != nil {
		if closeOnErr != nil {
			closeOnErr()
		}
		err = c.opError(he)
	}
	if wrote && (err != nil || !c.doneAfterRelay) {
		tr.handshakeDone(err)
	}
	return err
}

// blameCtx blames ctx or the deadline dl for a failure they may have caused.
func (c *Conn) blameCtx(ctx context.Context, he *HandshakeError, fired bool, dl time.Time) *HandshakeError {
	switch {
	case fired && (he == nil || !isServerMsgErr(he.Err)):
		if he == nil {
			he = &HandshakeError{Stage: c.h.readStage}
		}
		he.Err = ctx.Err()
	case he != nil && !dl.IsZero() && !isServerMsgErr(he.Err) && isTimeout(he.Err) && !time.Now().Before(dl):
		he.Err = context.DeadlineExceeded
	}
	return he
}

// unblock fails pending I/O on conn: a past deadline, or Close.
func unblock(conn net.Conn) {
	if conn.SetDeadline(time.Unix(1, 0)) != nil {
		conn.Close()
	}
}
