package socks0

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/internal/neterr"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	_ net.Conn      = (*Conn)(nil)
	_ io.ReaderFrom = (*Conn)(nil)
	_ io.WriterTo   = (*Conn)(nil)
	_ syscall.Conn  = (*Conn)(nil)
)

const maxEarlyData = 32 << 10

// aLongTimeAgo is a past deadline that wakes blocked I/O.
var aLongTimeAgo = time.Unix(1, 0)

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
	op               string   // of handshake errors
	network          string   // of errors
	proxyAddr        string   // Source of errors if it parses; else the conn's RemoteAddr
	laddr, raddr     net.Addr // Listener.Accept's
	replyTimeout     time.Duration
	handshakeTimeout time.Duration
	configTrace      *ClientTrace
	doneAfterRelay   bool // a successful UDP ASSOCIATE's HandshakeDone is the caller's

	// Fast paths that skip mu, kept by storeReadyLocked.
	readReady  atomic.Bool // replies consumed
	writeReady atomic.Bool // handshake written without error

	mu            sync.Mutex
	trace         *ClientTrace // nil until chosen by the claim (a Dialer's: by the dial)
	phase         phase
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

// phase is how far the handshake write went. The handshake can end (done) in
// any phase: a config error or cancellation in phaseIdle, replies that beat
// the end of the write in phaseSending.
type phase uint8

const (
	phaseIdle    phase = iota
	phaseSending       // a call claimed the handshake and is writing it (L0/L1: running it)
	phaseSent          // the handshake write is over
)

// Client returns a Conn that runs the handshake for target over conn (TCP,
// TLS, a mux stream). Names go to the proxy unresolved. Invalid arguments
// surface as the handshake error.
func Client(conn net.Conn, target string, cfg *Config) *Conn {
	a, err := wire.ParseAddr(target)
	return newClient(conn, a, cfg, err)
}

func ClientAddr(conn net.Conn, target wire.Addr, cfg *Config) *Conn {
	return newClient(conn, target, cfg, nil)
}

// newClient fails the handshake with parseErr, target's, if set; Config is
// applied anyway: its version shapes later errors.
func newClient(conn net.Conn, target wire.Addr, cfg *Config, parseErr error) *Conn {
	c := &Conn{conn: conn, op: opConnect, network: "tcp"}
	c.h.target, c.h.mu, c.h.buf = target, &c.mu, c.inline[:0] // target for config errors too
	err := errNoConn
	if conn != nil {
		if err = c.init(cfg, wire.CmdConnect, target); parseErr != nil {
			err = parseErr
		}
	}
	if err != nil {
		c.failLocked(&HandshakeError{StageConfig, err}) // c is not shared yet
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
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		c.abortWith(err) // now, not later on AfterFunc's goroutine
	} else if ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() { c.abortWith(ctx.Err()) })
		defer stop()
	}
	return c.handshake(ctx, opConnect, true)
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
	buf, p := c.earlyBuf(k)
	n, err := c.send(append(buf, b[:k]...))
	putEarlyBuf(p, len(buf)+k)
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
	err, claimed := c.checkLocked("readfrom"), c.phase != phaseIdle
	c.mu.Unlock()
	switch {
	case err != nil:
		return 0, true, err
	case claimed:
		return 0, false, c.waitWritten("readfrom")
	}
	hs := len(c.h.out)
	buf, p := c.earlyBuf(maxEarlyData)
	m, rerr := readSome(r, buf[hs:cap(buf)])
	eof := errors.Is(rerr, io.EOF)
	w, err := 0, rerr
	if m != 0 || eof {
		if w, err = c.sendFirstRead(buf[:hs+m]); err == nil && !eof {
			err = rerr
		}
	}
	putEarlyBuf(p, hs+m)
	return int64(w), err != nil || rerr != nil, err
}

// readSome reads until it gets data or an error.
func readSome(r io.Reader, b []byte) (n int, err error) {
	for n == 0 && err == nil {
		n, err = r.Read(b)
	}
	return n, err
}

// sendFirstRead sends b, the handshake and ReadFrom's first data, if this
// call claims the handshake; else the data alone, after the claimer's write.
func (c *Conn) sendFirstRead(b []byte) (int, error) {
	mustSend, err := c.claim(context.Background(), "readfrom")
	switch {
	case err != nil:
		return 0, err
	case mustSend:
		return c.send(b)
	}
	c.h.wipe(b) // its copy of the handshake is not sent
	if err := c.waitWritten("readfrom"); err != nil {
		return 0, err
	}
	n, err := c.conn.Write(b[len(c.h.out):])
	return n, c.ioErr("readfrom", err)
}

// maxHandshake fits the built-in handshakes (RFC 1929 auth included) in an
// earlyArray; a longer custom Pipeliner request gets an allocated buffer.
const maxHandshake = 1 << 10

type earlyArray [maxHandshake + maxEarlyData]byte

var earlyBufs = sync.Pool{New: func() any { return new(earlyArray) }}

// earlyBuf returns the handshake with room for n bytes of data, and the
// pooled array holding it, if any, for putEarlyBuf. A buffer of up to
// maxHandshake bytes is allocated: cheaper than refilling the pool after a GC.
func (c *Conn) earlyBuf(n int) ([]byte, *earlyArray) {
	hs := len(c.h.out)
	if hs > maxHandshake || hs+n <= maxHandshake {
		return append(make([]byte, 0, hs+n), c.h.out...), nil
	}
	p := earlyBufs.Get().(*earlyArray)
	return append(p[:0:hs+n], c.h.out...), p
}

// putEarlyBuf zeroes the used bytes of p, then pools it.
func putEarlyBuf(p *earlyArray, used int) {
	if p != nil {
		clear(p[:used])
		earlyBufs.Put(p)
	}
}

// WriteTo waits for the replies; splice applies.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if !c.readReady.Load() {
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
	if c.abortErr == nil && !c.done {
		c.abortErr = net.ErrClosed
	}
	c.storeReadyLocked()
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

// The handshake's state machine. c.phase only advances: phaseIdle, claimed by
// one call (run for L0/L1; claim then send for L2) to phaseSending, then
// phaseSent. Another call (L2: awaitReplies) may read the replies once the
// handshake is claimed. endLocked ends the handshake once (done), updating
// the fast paths and deciding whether HandshakeDone runs; abortWith and Close
// make it fail with abortErr once no call is working on it.

func (c *Conn) run(ctx context.Context, op string) error {
	c.mu.Lock()
	if mustRun, err := c.claimRunLocked(ctx, op); !mustRun {
		c.mu.Unlock()
		return err
	}
	tr := c.trace
	c.mu.Unlock()

	he := c.runTimed(ctx, tr)

	c.mu.Lock()
	c.endIOLocked(ctx)
	c.phase = phaseSent
	hook := c.endLocked(c.blame(he, c.abortErr, time.Time{}, nil))
	err := c.checkLocked(op)
	c.unlockDone(hook)
	return err
}

func (c *Conn) claimRunLocked(ctx context.Context, op string) (mustRun bool, err error) {
	for {
		if err := c.checkLocked(op); err != nil || c.done {
			return false, err
		}
		switch {
		case c.phase != phaseIdle:
			c.waitLocked(time.Time{})
		case c.abortErr != nil: // canceled before anything was sent
			c.endLocked(&HandshakeError{c.h.writeStage(0), c.abortErr})
		default:
			c.claimLocked(ctx)
			c.busy = true
			return true, nil
		}
	}
}

// runTimed uses a bare timer, not a timer ctx: a fifth of the allocations.
func (c *Conn) runTimed(ctx context.Context, tr *ClientTrace) *HandshakeError {
	if d, ok := c.handshakeBudget(ctx); ok {
		timer := time.AfterFunc(d, c.handshakeExpired)
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

// claimLocked moves to phaseSending, choosing the hooks unless a dial did.
func (c *Conn) claimLocked(ctx context.Context) {
	c.phase = phaseSending
	if c.trace == nil {
		c.trace = newTracer(ctx, c.configTrace)
	}
}

func (c *Conn) claim(ctx context.Context, op string) (mustSend bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(op); err != nil || c.phase != phaseIdle {
		return false, err
	}
	c.claimLocked(ctx)
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

// send writes b, the handshake and maybe data, for the call that claimed it.
// WroteHandshake runs before the handshake can end here, and a reader that
// ended it meanwhile left HandshakeDone to send (owed), so it runs last.
func (c *Conn) send(b []byte) (int, error) {
	n, werr := firstWrite(c.conn, b)
	c.h.wipe(b)
	hs := len(c.h.out)
	c.trace.wroteHandshake(werr) // c.trace was set by claim on this goroutine
	c.mu.Lock()
	owed := c.done // claim saw it not done
	c.phase = phaseSent
	if werr != nil && n < hs {
		he := c.blame(&HandshakeError{c.h.writeStage(n), werr}, c.abortErr, time.Time{}, nil)
		hook := c.endLocked(he) || owed
		if c.err == nil { // the replies came first, yet the proxy lacks the request
			c.err = c.opError(he)
			c.storeReadyLocked()
		}
		err := c.err
		c.unlockDone(hook)
		return 0, err
	}
	c.storeReadyLocked()
	c.unlockDone(c.settleLocked() || owed)
	return n - hs, c.ioErr("write", werr)
}

func (c *Conn) waitWritten(op string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.phase != phaseSent && !c.done && !c.closed {
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
	if d, ok := c.replyBudget(ctx); ok {
		replyDeadline = time.Now().Add(d)
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
	hook := c.endLocked(c.blame(he, c.abortErr, replyDeadline, os.ErrDeadlineExceeded))
	err := c.checkLocked(op)
	c.unlockDone(hook)
	return err
}

func (c *Conn) waitClaimedLocked(op string) error {
	for c.phase == phaseIdle && !c.done && !c.closed {
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
		if c.abortErr != nil && c.phase == phaseSent && !c.busy {
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

// blame picks the error of a failed (he) or interrupted (he nil) handshake.
// A server message stands. Else cause, if any (cancellation, Close, the
// handshake timer), explains it; else expired replaces a timeout of the
// handshake's own deadline dl, unless the caller's read deadline came first.
func (c *Conn) blame(he *HandshakeError, cause error, dl time.Time, expired error) *HandshakeError {
	switch {
	case he != nil && isServerMsgErr(he.Err):
	case cause != nil:
		if he == nil {
			he = &HandshakeError{Stage: c.h.readStage}
		}
		he.Err = cause
	case he != nil && c.expired(he.Err, dl):
		he.Err = expired
	}
	return he
}

func (c *Conn) expired(err error, dl time.Time) bool {
	return !dl.IsZero() && neterr.IsTimeout(err) && !time.Now().Before(dl) &&
		(c.readDeadline.IsZero() || dl.Before(c.readDeadline))
}

func (c *Conn) abortWith(err error) {
	if c.conn == nil {
		return
	}
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
func (c *Conn) settleUnlock() { c.unlockDone(c.settleLocked()) }

// settleLocked is settleUnlock without the unlock: it reports whether
// HandshakeDone must run.
func (c *Conn) settleLocked() (hook bool) {
	if c.abortErr != nil && c.phase == phaseSent && !c.busy {
		hook = c.endLocked(c.blame(nil, c.abortErr, time.Time{}, nil))
	}
	c.broadcastLocked()
	return hook
}

// unlockDone unlocks c.mu, then runs HandshakeDone if hook.
func (c *Conn) unlockDone(hook bool) {
	tr, err := c.trace, c.err
	c.mu.Unlock()
	if hook {
		tr.handshakeDone(err)
	}
}

// endLocked ends the handshake, established if he is nil, unless it is over;
// it reports whether HandshakeDone must run now: whether the handshake was
// written. While it is being written (ModeEarly), send runs HandshakeDone.
func (c *Conn) endLocked(he *HandshakeError) bool {
	switch {
	case c.done:
		return false
	case he == nil:
		c.establishLocked(c.h.bound)
	default:
		c.failLocked(he)
	}
	return c.phase == phaseSent
}

func (c *Conn) establishLocked(bound wire.Addr) {
	c.done, c.bound = true, bound
	c.broadcastLocked()
	c.storeReadyLocked()
}

func (c *Conn) failLocked(he *HandshakeError) {
	c.done, c.err = true, c.opError(he)
	c.broadcastLocked()
	c.storeReadyLocked()
	// Unblock other calls' handshake I/O: they return c.err.
	if c.busy {
		c.conn.SetReadDeadline(aLongTimeAgo)
	}
	if c.phase == phaseSending {
		c.conn.SetWriteDeadline(aLongTimeAgo)
	}
}

// storeReadyLocked updates the fast paths from the state.
func (c *Conn) storeReadyLocked() {
	ok := c.err == nil && !c.closed
	c.readReady.Store(ok && c.done)
	c.writeReady.Store(ok && c.phase == phaseSent)
}

func (c *Conn) checkLocked(op string) error {
	switch {
	case c.conn == nil:
		return c.noConn(op)
	case !c.closed:
		return c.err
	case op != opConnect:
		return c.connErr(op, net.ErrClosed)
	case c.phase != phaseIdle:
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
	e := &net.OpError{Op: c.op, Net: c.network, Err: he}
	if proxy, ok := c.proxy(); ok {
		e.Source = proxy
	} else if c.conn != nil {
		e.Source = c.conn.RemoteAddr()
	}
	if c.h.target.IsValid() {
		e.Addr = c.h.target
	}
	return e
}

// proxy is the Dialer's ProxyAddr, parsed on the error path only.
func (c *Conn) proxy() (wire.Addr, bool) {
	if c.proxyAddr == "" {
		return wire.Addr{}, false
	}
	a, err := wire.ParseAddr(c.proxyAddr)
	return a, err == nil
}

func (c *Conn) connErr(op string, err error) error {
	return &net.OpError{Op: op, Net: c.network, Source: c.conn.LocalAddr(), Addr: c.conn.RemoteAddr(), Err: err}
}

// ioErr maps an I/O error after Close to net.ErrClosed.
func (c *Conn) ioErr(op string, err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return err
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
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

// handshakeBudget is HandshakeTimeout's bound on a handshake under ctx: zero
// is defaultHandshakeTimeout unless ctx has a deadline; negative is none.
func (c *Conn) handshakeBudget(ctx context.Context) (time.Duration, bool) {
	switch t := c.handshakeTimeout; {
	case t > 0:
		return t, true
	case t < 0 || hasDeadline(ctx):
		return 0, false
	}
	return defaultHandshakeTimeout, true
}

// replyBudget is ReplyTimeout, else the handshake budget.
func (c *Conn) replyBudget(ctx context.Context) (time.Duration, bool) {
	if c.replyTimeout > 0 {
		return c.replyTimeout, true
	}
	return c.handshakeBudget(ctx)
}

// handshakeCtx bounds ctx by the handshake budget.
func (c *Conn) handshakeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if d, ok := c.handshakeBudget(ctx); ok {
		return context.WithTimeout(ctx, d)
	}
	return ctx, nil
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

// handshakeOver runs a Dialer's or Request's handshake on conn, closing it on
// error if closeOnErr; dl is conn's deadline, the HandshakeTimeout.
func (c *Conn) handshakeOver(ctx context.Context, conn net.Conn, closeOnErr bool, dl time.Time) error {
	var stop func() bool
	if ctx.Done() != nil {
		stop = context.AfterFunc(ctx, func() { unblock(conn) })
	}
	he := c.h.run(ctx, conn, c.trace)
	var cause error
	if stop != nil && !stop() { // it fired
		cause = ctx.Err()
	}
	var err error
	if he = c.blame(he, cause, dl, context.DeadlineExceeded); he != nil {
		if closeOnErr {
			conn.Close()
		}
		err = c.opError(he)
	}
	if err != nil || !c.doneAfterRelay {
		c.trace.handshakeDone(err)
	}
	return err
}

// unblock fails pending I/O on conn: a past deadline, or Close.
func unblock(conn net.Conn) {
	if conn.SetDeadline(aLongTimeAgo) != nil {
		conn.Close()
	}
}
