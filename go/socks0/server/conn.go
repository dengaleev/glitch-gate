package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

const (
	inSize         = 2 << 10 // the largest handshake (1032 B for SOCKS5) plus early data
	maxAuthMsg     = 1 << 10
	outSize        = 2 + maxAuthMsg + wire.MaxReplyLen
	lingerMaxBytes = 64 << 10
	lingerTime     = 500 * time.Millisecond
)

// buffers is pooled unless a slice reached user code (serverConn.exposed), so a slice kept too
// long never shows another conn's bytes (B2).
type buffers struct {
	in      [inSize]byte
	out     [outSize]byte
	methods [255]wire.Method
}

var bufPool = sync.Pool{New: func() any { return new(buffers) }}

func getBuffers() *buffers { return bufPool.Get().(*buffers) }

func putBuffers(b *buffers) {
	if b != nil {
		clear(b.in[:])
		clear(b.out[:])
		bufPool.Put(b)
	}
}

var (
	zeroBound    = wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	aLongTimeAgo = time.Unix(1, 0)
)

type closeWriter interface{ CloseWrite() error }

type serverConn struct {
	s            *Server
	nc           net.Conn
	parent       context.Context // from BaseContext, ConnContext or ServeConn
	ctx          context.Context // the handler's; whatever cancels it closes nc too (Relay relies on it)
	cancel       context.CancelFunc
	state        atomic.Uint32 // ConnState
	admitRelease func()

	// Owned by the serving goroutine until Reply.
	bufp           *buffers
	r, w           int       // unread input is bufp.in[r:w]
	readErr        error     // sticky; comes after the bytes in [r:w] (I6)
	out            []byte    // queued writes (I7), in bufp.out
	writeErr       error     // sticky
	outStage       string    // of the message queued last
	deadline       time.Time // of the handshake
	authenticating bool
	lastMsg        [2]int // the last AuthConn message's bounds in bufp.in
	linger         bool   // a failure reply or status went out (S1)
	exposed        bool   // see buffers; guarded by mu after the handshake

	mu        sync.Mutex // guards the fields below and bufp after the handshake
	replied   bool       // a final reply was written, or failed
	listening bool       // ReplyListening done
	done      bool
	reading   bool // a Conn read uses the buffer outside mu
	handedOff atomic.Bool
	drained   atomic.Bool // no buffered bytes, no sticky error: reads go to nc

	recv, sent atomic.Int64
	ro         readerOnly // for Conn.WriteTo and ReadFrom without WriterTo, ReaderFrom
	wo         writerOnly

	req  Request
	conn Conn
	auth AuthConn

	scratch ownHostScratch
}

// ownHostScratch spares checkOwnHost an allocation when free.
type ownHostScratch struct {
	busy atomic.Bool
	req  Request
	addr net.TCPAddr
	ip   [16]byte
}

func (sc *serverConn) serve() (err error) {
	s := sc.s
	var r *Request
	defer func() {
		if p := recover(); p != nil {
			err = sc.recovered(p)
		}
		err = sc.finish(r, err)
	}()
	if sc.parent.Done() != nil {
		defer context.AfterFunc(sc.parent, func() { sc.nc.Close() })()
	}
	s.setState(sc.nc, StateNew)
	if s.Admit != nil {
		if sc.admitRelease, err = s.Admit(sc.ctx, sc.nc); err != nil {
			return err
		}
	}
	if stage, err := sc.handshake(); err != nil {
		_ = sc.flush()
		return sc.opError(stage, err)
	}
	if !sc.activate() {
		return ErrServerClosed
	}
	r = &sc.req
	s.Trace.gotRequest(sc.ctx, r)
	if s.Allow != nil {
		if err := s.Allow(sc.ctx, r); err != nil {
			return err
		}
	}
	return s.cfg.handler.ServeSOCKS(sc.ctx, r)
}

func (sc *serverConn) activate() bool {
	if !sc.state.CompareAndSwap(uint32(StateNew), uint32(StateActive)) {
		return false
	}
	sc.s.inHandshake.Add(-1)
	sc.s.setState(sc.nc, StateActive)
	return true
}

func (sc *serverConn) recovered(p any) error {
	buf := make([]byte, 64<<10)
	buf = buf[:runtime.Stack(buf, false)]
	v := fmt.Sprintf("%q", fmt.Sprint(p))
	sc.s.logf("socks0/server: panic serving %v: %s\n%s", sc.nc.RemoteAddr(), v, buf)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return &panicError{value: v, replied: sc.replied}
}

// finish replies if the handler did not (never success, B1).
func (sc *serverConn) finish(r *Request, err error) error {
	s := sc.s
	sc.cancel()
	if r != nil && sc.fallbackReply(err) && err == nil {
		err = ErrNoReply
	}
	sc.end()
	sc.state.Store(uint32(StateClosed))
	if r == nil { // never activated
		s.inHandshake.Add(-1)
	}
	s.Trace.done(sc.ctx, r, sc.stats(), err)
	s.setState(sc.nc, StateClosed)
	s.untrack(sc)
	if sc.admitRelease != nil {
		sc.admitRelease()
	}
	return err
}

func (sc *serverConn) fallbackReply(err error) bool {
	sc.mu.Lock()
	if sc.replied || sc.done {
		sc.mu.Unlock()
		return false
	}
	sc.replied = true
	rep := ReplyFor(err)
	if isSuccess(rep) {
		rep = wire.ReplyGeneralFailure
	}
	werr := sc.writeReply(rep, wire.Addr{})
	sc.linger = werr == nil
	sc.mu.Unlock()
	sc.s.Trace.replied(sc.ctx, rep, wire.Addr{}, werr)
	return true
}

func (sc *serverConn) end() {
	sc.mu.Lock()
	sc.done = true
	b := sc.bufp
	if sc.reading {
		b = nil // the reader releases it
	} else {
		sc.bufp = nil
	}
	if sc.exposed {
		b = nil
	}
	sc.mu.Unlock()
	if sc.linger {
		sc.lingerClose(b)
	}
	sc.nc.Close()
	putBuffers(b)
}

// lingerClose reads what the client still sends (≤ 64 KiB, ≤ 500 ms) after the FIN: closing with
// unread data would reset the conn and destroy the reply in flight (S1).
func (sc *serverConn) lingerClose(b *buffers) {
	cw, ok := sc.nc.(closeWriter)
	if !ok || cw.CloseWrite() != nil {
		return
	}
	if b == nil {
		b = getBuffers()
		defer putBuffers(b)
	}
	_ = sc.nc.SetReadDeadline(time.Now().Add(lingerTime))
	for n := 0; n < lingerMaxBytes; {
		m, err := sc.nc.Read(b.in[:])
		if n += m; err != nil {
			return
		}
	}
}

func (sc *serverConn) stats() ConnStats {
	return ConnStats{Received: sc.recv.Load(), Sent: sc.sent.Load()}
}

func (sc *serverConn) opError(stage string, err error) error {
	e := &net.OpError{Op: "socks serve", Source: sc.nc.LocalAddr(), Addr: sc.nc.RemoteAddr(), Err: &socks0.HandshakeError{Stage: stage, Err: err}}
	if e.Source != nil {
		e.Net = e.Source.Network()
	}
	return e
}

// handshake leaves every byte after the request in the buffer; stage is the message that failed.
func (sc *serverConn) handshake() (stage string, err error) {
	sc.beginHandshake()
	stage, err = sc.negotiate()
	if err == nil {
		err = sc.flush()
	}
	if sc.writeErr != nil {
		return sc.outStage, sc.writeErr
	}
	if err == nil && sc.s.cfg.handshakeTimeout > 0 {
		_ = sc.nc.SetDeadline(time.Time{})
	}
	return stage, err
}

func (sc *serverConn) beginHandshake() {
	if t := sc.s.cfg.handshakeTimeout; t > 0 {
		sc.deadline = time.Now().Add(t)
		_ = sc.nc.SetDeadline(sc.deadline)
	}
	sc.req.LocalAddr, sc.req.RemoteAddr = sc.nc.LocalAddr(), sc.nc.RemoteAddr()
	sc.bufp = getBuffers()
	sc.out = sc.bufp.out[:0]
}

func (sc *serverConn) negotiate() (string, error) {
	if err := sc.fill(1); err != nil {
		return wire.StageGreeting, truncated(wire.StageGreeting, err)
	}
	versions := sc.s.cfg.versions
	switch v := sc.bufp.in[0]; {
	case v == wire.Version5 && versions&V5 != 0:
		return sc.handshake5()
	case v == wire.Version4 && versions&V4 != 0:
		return sc.handshake4()
	default:
		return wire.StageGreeting, &wire.ProtocolError{Stage: wire.StageGreeting, Field: wire.FieldVER, Got: v}
	}
}

func (sc *serverConn) handshake5() (string, error) {
	if stage, err := sc.authenticate5(); err != nil {
		return stage, err
	}
	return sc.readRequest5()
}

func (sc *serverConn) authenticate5() (string, error) {
	s := sc.s
	methods, err := sc.readGreeting()
	if err != nil {
		return wire.StageGreeting, err
	}
	a := s.cfg.choose(methods)
	if a == nil {
		sc.queue(wire.AppendMethodSelection(sc.out, wire.MethodNoAcceptable), wire.StageMethodSelection)
		sc.linger = true
		return wire.StageGreeting, &MethodError{Offered: slices.Clone(methods)}
	}
	m := a.Method()
	sc.queue(wire.AppendMethodSelection(sc.out, m), wire.StageMethodSelection)
	sc.req.Method = m
	id, err := sc.authenticate(a)
	s.Trace.authDone(sc.ctx, m, id, err)
	if err != nil {
		return authStage(m), err
	}
	sc.req.Identity = id
	return "", nil
}

func authStage(m wire.Method) string {
	if m == wire.MethodUserPass {
		return wire.StageUserPass
	}
	return socks0.StageAuth
}

func (sc *serverConn) readGreeting() ([]wire.Method, error) {
	b := sc.bufp
	var methods []wire.Method
	if _, err := sc.next(wire.StageGreeting, 2+255, func(p []byte) (n int, err error) {
		methods, n, err = wire.ParseGreeting(b.methods[:0], p)
		return n, err
	}); err != nil {
		return nil, err
	}
	if t := sc.s.Trace; t != nil && t.GotGreeting != nil {
		sc.exposed = true
	}
	sc.s.Trace.gotGreeting(sc.ctx, methods)
	return methods, nil
}

func (sc *serverConn) readRequest5() (string, error) {
	var cmd wire.Command
	var addr wire.Addr
	if _, err := sc.next(wire.StageRequest, wire.MaxReplyLen, func(p []byte) (n int, err error) {
		cmd, addr, n, err = wire.ParseRequest(p)
		return n, err
	}); err != nil {
		// A whole request with a bad ATYP or ADDR gets 08.
		if pe, ok := errors.AsType[*wire.ProtocolError](err); ok && pe.Field != wire.FieldVER && pe.Err == nil {
			sc.req.Version = V5
			sc.replyNow(wire.ReplyAddressTypeNotSupported)
		}
		return wire.StageRequest, err
	}
	sc.req.Version, sc.req.Command, sc.req.Addr = V5, cmd, addr
	return "", nil
}

func (sc *serverConn) handshake4() (string, error) {
	var cmd wire.Command
	var addr wire.Addr
	var uid []byte
	if _, err := sc.next(wire.StageRequest4, 8+256+256, func(p []byte) (n int, err error) {
		cmd, addr, uid, n, err = wire.ParseRequest4(p)
		return n, err
	}); err != nil {
		return wire.StageRequest4, err
	}
	defer clear(uid)
	sc.req.Version, sc.req.Command, sc.req.Addr, sc.req.Method = V4, cmd, addr, wire.MethodNoAuth
	if err := sc.authorize4(cmd, uid); err != nil {
		sc.replyNow(wire.Reply4Rejected)
		return wire.StageRequest4, err
	}
	return "", nil
}

// authorize4 admits only by UserID or the built-in NoAuth (no SOCKS5 auth bypass).
func (sc *serverConn) authorize4(cmd wire.Command, uid []byte) error {
	s := sc.s
	if cmd != wire.CmdConnect && cmd != wire.CmdBind {
		return errSOCKS4Cmd
	}
	switch {
	case s.UserID != nil:
		sc.exposed = true // uid aliases the buffer
		ctx, cancel := sc.authCtx()
		id, err := s.UserID(ctx, uid)
		cancel()
		s.Trace.authDone(sc.ctx, wire.MethodUserPass, id, err)
		if err != nil {
			return fmt.Errorf("%w: %w", socks0.ErrAuthFailed, err)
		}
		sc.req.Identity, sc.req.Method = id, wire.MethodUserPass
	case !s.cfg.builtinNoAuth:
		return errSOCKS4Auth
	}
	return nil
}

func (sc *serverConn) authCtx() (context.Context, context.CancelFunc) {
	if sc.deadline.IsZero() {
		return sc.ctx, func() {}
	}
	return context.WithDeadline(sc.ctx, sc.deadline)
}

func (sc *serverConn) authenticate(a Authenticator) (any, error) {
	if _, ok := a.(NoAuth); ok {
		return nil, nil
	}
	ctx := sc.ctx
	if up, ok := a.(UserPass); !ok || up.Check != nil { // a Users lookup needs no deadline ctx
		var cancel context.CancelFunc
		ctx, cancel = sc.authCtx()
		defer cancel()
	}
	mark := len(sc.out)
	sc.authenticating = true
	id, err := a.Authenticate(ctx, &sc.auth)
	sc.authenticating = false
	sc.clearLastMsg()
	switch {
	case err == nil:
	case errors.Is(err, socks0.ErrAuthFailed):
		sc.linger = true
	case len(sc.out) >= mark:
		sc.out = sc.out[:mark] // only rejections send their status
	}
	return id, err
}

func (sc *serverConn) queue(out []byte, stage string) {
	sc.out, sc.outStage = out, stage
}

func (sc *serverConn) replyNow(rep wire.Reply) {
	sc.replied = true
	out, _ := sc.appendReply(sc.out, rep, wire.Addr{})
	sc.queue(out, wire.StageReply)
	err := sc.flush()
	sc.linger = err == nil
	sc.s.Trace.replied(sc.ctx, rep, wire.Addr{}, err)
}

// next reads only when parse asks for more (I1, I2).
func (sc *serverConn) next(stage string, limit int, parse func([]byte) (int, error)) ([]byte, error) {
	for {
		b := sc.bufp.in[sc.r:sc.w:sc.w]
		n, err := parse(b)
		switch {
		case err == nil && (n < 0 || n > len(b)):
			return nil, &wire.ProtocolError{Stage: stage, Err: errContract}
		case err == nil:
			sc.r += n
			return b[:n:n], nil
		case !errors.Is(err, wire.ErrIncomplete):
			return nil, err
		}
		n = max(n, len(b)+1)
		if n > limit {
			return nil, &wire.ProtocolError{Stage: stage, Err: errTooLong}
		}
		if err := sc.fill(n); err != nil && sc.w-sc.r == len(b) {
			return nil, truncated(stage, err)
		}
	}
}

// fill: a read error is sticky and comes after the bytes read with it.
func (sc *serverConn) fill(need int) error {
	for sc.w-sc.r < need {
		if sc.readErr != nil {
			return sc.readErr
		}
		if err := sc.flush(); err != nil {
			return err
		}
		in := sc.bufp.in[:]
		if sc.r+need > len(in) {
			sc.w, sc.r = copy(in, in[sc.r:sc.w]), 0
		}
		n, err := sc.nc.Read(in[sc.w:])
		sc.w += n
		sc.readErr = err
	}
	return nil
}

func (sc *serverConn) flush() error {
	if sc.writeErr != nil || len(sc.out) == 0 {
		return sc.writeErr
	}
	_, sc.writeErr = sc.nc.Write(sc.out)
	sc.out = sc.out[:0]
	return sc.writeErr
}

func (sc *serverConn) clearLastMsg() {
	if sc.bufp != nil && sc.lastMsg[1] > sc.lastMsg[0] {
		clear(sc.bufp.in[sc.lastMsg[0]:sc.lastMsg[1]])
	}
	sc.lastMsg = [2]int{}
}

func truncated(stage string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &wire.ProtocolError{Stage: stage, Err: io.ErrUnexpectedEOF}
	}
	return err
}

// writeReply: sc.mu is held, or the handshake goroutine owns the conn.
func (sc *serverConn) writeReply(rep wire.Reply, bound wire.Addr) error {
	if sc.bufp == nil {
		return net.ErrClosed
	}
	out, err := sc.appendReply(sc.bufp.out[:0], rep, bound)
	if err != nil {
		return err
	}
	if t := sc.s.cfg.handshakeTimeout; t > 0 {
		_ = sc.nc.SetWriteDeadline(time.Now().Add(t))
	}
	_, err = sc.nc.Write(out)
	return err
}

// appendReply: SOCKS4 maps REP to 0x5A–0x5D and a non-IPv4 bound to 0.0.0.0:0 (S9).
func (sc *serverConn) appendReply(dst []byte, rep wire.Reply, bound wire.Addr) ([]byte, error) {
	if sc.req.Version == V4 {
		switch {
		case rep == wire.ReplySucceeded:
			rep = wire.Reply4Granted
		case rep < wire.Reply4Granted || rep > wire.Reply4IdentMismatch:
			rep = wire.Reply4Rejected
		}
		if !bound.IP().Is4() {
			bound = wire.Addr{}
		}
		return wire.AppendReply4(dst, rep, bound)
	}
	if !bound.IsValid() {
		bound = zeroBound
	}
	return wire.AppendReply(dst, rep, bound)
}

func isSuccess(rep wire.Reply) bool { return rep == wire.ReplySucceeded || rep == wire.Reply4Granted }
