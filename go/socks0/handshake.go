package socks0

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	errNilUserPass  = errors.New("socks0: Auth is a nil *UserPass")
	errNoAcceptable = errors.New("socks0: Auth.Method is MethodNoAcceptable")
	errNoConn       = errors.New("socks0: no conn")
	errLongAuth     = errors.New("socks0: Pipeliner.ParseReply asked for over 64 KiB")
	errAuthSOCKS4   = errors.New("socks0: SOCKS4 takes only a UserPass without Password (USERID)")
	errOfferNoAuth  = errors.New("socks0: OfferNoAuth requires ModeSequential and SOCKS5")
	errLongUserPass = fmt.Errorf("%w: username or password over 255 bytes", wire.ErrInvalid)
)

// maxReplyBytes: a custom Pipeliner may ask for any length.
const maxReplyBytes = 64 << 10

// handshake holds no inline buffers, so a Dialer's L0/L1 handshake can live on
// the stack; out and rbuf share one allocation.
type handshake struct {
	mode         Mode
	version      uint8 // 4 or 5
	cmd          wire.Command
	userID       string        // SOCKS4
	auth         Authenticator // nil offers MethodNoAuth
	pipe         Pipeliner     // auth, if it is one
	offered      wire.Method
	offerNoAuth  bool // besides offered
	method       wire.Method
	authReqStage string
	authRepStage string
	authLen      int // of the auth request
	authMin      int // shortest auth reply, read ahead with the method selection
	userPass     bool
	username     string
	password     string
	authRequest  []byte // a non-UserPass Pipeliner's
	buf          []byte // out, then rbuf
	out          []byte // greeting, auth request (not in ModeSequential), request
	greetingEnd  int    // in out
	authEnd      int    // in out
	target       wire.Addr

	readStage string
	mu        *sync.Mutex // if set, held to write readStage, which other Conn calls read
	rbuf      []byte
	msgStart  int   // in rbuf
	filled    int   // bytes in rbuf
	readErr   error // reported once the bytes before it are parsed
	bound     wire.Addr
}

func (h *handshake) init(cfg *Config, cmd wire.Command) error {
	h.mode, h.cmd = cfg.Mode, cmd
	if h.mode > ModeEarly {
		return fmt.Errorf("socks0: unknown %v", h.mode)
	}
	if h.mode == ModeEarly && cmd != wire.CmdConnect {
		h.mode = ModePipelined
	}
	switch cfg.Version {
	case 0, 5:
		h.version = 5
		return h.init5(cfg)
	case 4:
		h.version = 4
		if cfg.OfferNoAuth {
			return errOfferNoAuth
		}
		return h.init4(cfg.Auth)
	}
	return fmt.Errorf("socks0: unknown Config.Version %d", cfg.Version)
}

func (h *handshake) init5(cfg *Config) error {
	if cfg.OfferNoAuth && h.mode != ModeSequential {
		return errOfferNoAuth
	}
	h.offered, h.authReqStage, h.authRepStage = wire.MethodNoAuth, StageAuth, StageAuth
	if cfg.Auth == nil {
		return nil
	}
	if err := h.setAuth(cfg.Auth, cfg.OfferNoAuth); err != nil {
		return err
	}
	if h.pipe == nil {
		return nil
	}
	return h.preparePipelined()
}

func (h *handshake) setAuth(a Authenticator, offerNoAuth bool) error {
	switch up := a.(type) {
	case *UserPass:
		if up == nil {
			return errNilUserPass
		}
		h.setUserPass(*up)
	case UserPass:
		h.setUserPass(up)
	}
	if h.offered = a.Method(); h.offered == wire.MethodNoAcceptable {
		return errNoAcceptable
	}
	h.auth, h.offerNoAuth = a, offerNoAuth && h.offered != wire.MethodNoAuth
	h.pipe, _ = a.(Pipeliner)
	if h.pipe == nil && h.mode != ModeSequential {
		return ErrNotPipelinable
	}
	return nil
}

func (h *handshake) setUserPass(up UserPass) {
	h.userPass, h.username, h.password = true, up.Username, up.Password
	h.authReqStage, h.authRepStage = wire.StageUserPass, wire.StageUserPassStatus
}

func (h *handshake) preparePipelined() error {
	if h.userPass {
		if len(h.username) > 255 || len(h.password) > 255 {
			return errLongUserPass
		}
		h.authLen = 3 + len(h.username) + len(h.password)
	} else {
		b, err := h.pipe.AppendRequest(nil)
		if err != nil {
			return err
		}
		h.authRequest, h.authLen = b, len(b)
	}
	if n, err := h.pipe.ParseReply(nil); errors.Is(err, wire.ErrIncomplete) {
		h.authMin = max(n, 0)
	}
	return nil
}

func (h *handshake) init4(auth Authenticator) error {
	if h.cmd != wire.CmdConnect && h.cmd != wire.CmdBind {
		return fmt.Errorf("socks0: SOCKS4 has no %v: %w", h.cmd, errors.ErrUnsupported)
	}
	switch a := auth.(type) {
	case nil:
	case *UserPass:
		if a == nil {
			return errNilUserPass
		}
		return h.init4(*a)
	case UserPass:
		if a.Password != "" {
			return errAuthSOCKS4
		}
		h.userID = a.Username
	default:
		return errAuthSOCKS4
	}
	return nil
}

func (h *handshake) setTarget(a wire.Addr) error {
	n, rlen := 3+wire.UDPHeaderLen(a), 2+h.authMin+22 // 22: a reply with an IPv6 BND
	if h.mode != ModeSequential {
		n += h.authLen
	}
	if h.offerNoAuth {
		n++
	}
	if h.version == 4 {
		n, rlen = 8+len(h.userID)+1+len(a.Name())+1, 8
	}
	if cap(h.buf) < n+rlen {
		h.buf = make([]byte, n+rlen)
	}
	out := h.buf[:0:n]
	var err error
	if h.version == 4 {
		out, err = wire.AppendRequest4(out, h.cmd, a, h.userID)
	} else {
		out, err = h.append5(out, a)
	}
	if err != nil {
		return err
	}
	h.target, h.out = a, out
	h.readStage, h.rbuf = h.writeStage(len(out)), h.buf[n:n+rlen]
	if h.version == 5 {
		h.readStage = wire.StageMethodSelection
	}
	return nil
}

func (h *handshake) append5(out []byte, a wire.Addr) ([]byte, error) {
	if h.offerNoAuth {
		out, _ = wire.AppendGreeting(out, h.offered, wire.MethodNoAuth)
	} else {
		out, _ = wire.AppendGreeting(out, h.offered) // one method: never fails
	}
	h.greetingEnd = len(out)
	switch {
	case h.mode == ModeSequential:
	case h.userPass:
		out, _ = wire.AppendUserPass(out, h.username, h.password) // checked in init
	default:
		out = append(out, h.authRequest...)
	}
	h.authEnd = len(out)
	return wire.AppendRequest(out, h.cmd, a)
}

func (h *handshake) replyStage() string {
	if h.version == 4 {
		return wire.StageReply4
	}
	return wire.StageReply
}

func (h *handshake) writeStage(n int) string {
	switch {
	case h.version == 4 && n < len(h.out):
		return wire.StageRequest4
	case h.version == 4:
		return wire.StageReply4
	case n < h.greetingEnd:
		return wire.StageGreeting
	case n < h.authEnd:
		return h.authReqStage
	}
	return wire.StageRequest
}

func (h *handshake) run(ctx context.Context, conn net.Conn, tr tracer) (wrote bool, he *HandshakeError) {
	if h.mode == ModeSequential && h.version == 5 {
		return true, h.runSequential(ctx, conn, tr)
	}
	n, err := firstWrite(conn, h.out)
	h.wipe(nil)
	tr.wroteHandshake(err)
	if err != nil {
		return true, &HandshakeError{h.writeStage(n), err}
	}
	return true, h.readReplies(conn, tr)
}

// wipe zeroes written credentials in out and in b, a copy (best effort).
func (h *handshake) wipe(b []byte) {
	if h.authEnd <= len(h.out) {
		clear(h.out[h.greetingEnd:h.authEnd])
	}
	if h.authEnd <= len(b) {
		clear(b[h.greetingEnd:h.authEnd])
	}
	clear(h.authRequest)
}

func (h *handshake) runSequential(ctx context.Context, conn net.Conn, tr tracer) *HandshakeError {
	_, err := firstWrite(conn, h.out[:h.greetingEnd])
	tr.wroteHandshake(err)
	if err != nil {
		return &HandshakeError{wire.StageGreeting, err}
	}
	if he := h.readMethod(conn, 0, tr); he != nil {
		return he
	}
	if h.auth != nil && h.method == h.offered {
		if he := h.authenticate(ctx, conn, tr); he != nil {
			return he
		}
	}
	if _, err := conn.Write(h.out[h.authEnd:]); err != nil {
		return &HandshakeError{wire.StageRequest, err}
	}
	return h.readReply(conn, tr)
}

func (h *handshake) authenticate(ctx context.Context, conn net.Conn, tr tracer) *HandshakeError {
	rw := &countingWriter{ReadWriter: conn}
	err := h.auth.Authenticate(ctx, rw)
	tr.authDone(err)
	if err == nil {
		return nil
	}
	stage := h.authRepStage
	if pe, ok := errors.AsType[*ProtocolError](err); ok {
		stage = pe.Stage
	} else if rw.n < h.authLen {
		stage = h.authReqStage
	}
	return &HandshakeError{stage, err}
}

type countingWriter struct {
	io.ReadWriter
	n int
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ReadWriter.Write(b)
	w.n += n
	return n, err
}

func (h *handshake) readReplies(r io.Reader, tr tracer) *HandshakeError {
	if h.version == 4 {
		return h.readReply(r, tr)
	}
	ahead := 5 // the shortest reply is longer
	if h.pipe != nil {
		ahead += h.authMin
	}
	if he := h.readMethod(r, ahead, tr); he != nil {
		return he
	}
	if h.pipe != nil {
		err := h.readNext(r, h.authRepStage, 5, h.pipe.ParseReply)
		tr.authDone(err)
		if err != nil {
			return h.fail(err)
		}
	}
	return h.readReply(r, tr)
}

func (h *handshake) readMethod(r io.Reader, ahead int, tr tracer) *HandshakeError {
	var m wire.Method
	err := h.readNext(r, wire.StageMethodSelection, ahead, func(b []byte) (n int, err error) {
		m, n, err = wire.ParseMethodSelection(b)
		return n, err
	})
	if err != nil {
		return h.fail(err)
	}
	tr.gotMethod(m)
	if h.method = m; m != h.offered && (!h.offerNoAuth || m != wire.MethodNoAuth) {
		return h.fail(&MethodError{Offered: h.offered, Selected: m, OfferedNoAuth: h.offerNoAuth})
	}
	return nil
}

func (h *handshake) readReply(r io.Reader, tr tracer) *HandshakeError {
	rep, bound, err := h.nextReply(r)
	if _, ok := err.(*ReplyError); ok || err == nil {
		tr.gotReply(rep, bound)
	}
	if err == nil {
		err = h.checkBound(bound)
	}
	if err != nil {
		return h.fail(err)
	}
	h.bound = bound
	return nil
}

func (h *handshake) nextReply(r io.Reader) (rep wire.Reply, bound wire.Addr, err error) {
	var gotVerRep bool
	ok, ver := wire.ReplySucceeded, byte(wire.Version5)
	if h.version == 4 {
		ok, ver = wire.Reply4Granted, 0
	}
	err = h.readNext(r, h.replyStage(), 0, func(b []byte) (n int, err error) {
		if h.version == 4 {
			rep, bound, n, err = wire.ParseReply4(b)
		} else {
			rep, bound, n, err = wire.ParseReply(b, h.cmd)
		}
		gotVerRep = len(b) > 1 && b[0] == ver
		return n, err
	})
	if gotVerRep && rep != ok {
		if err != nil {
			bound = wire.Addr{}
		}
		return rep, bound, &ReplyError{Reply: rep, Bound: bound, Version: h.version}
	}
	return rep, bound, err
}

func (h *handshake) readSecondReply(r io.Reader) (wire.Addr, error) {
	h.msgStart, h.filled = 0, 0
	_, peer, err := h.nextReply(r)
	return peer, err
}

// checkBound rejects a hostile BND that cmd cannot use.
func (h *handshake) checkBound(bound wire.Addr) error {
	switch cmd := h.cmd; {
	case (cmd == wire.CmdUDPAssociate || cmd == wire.CmdBind) && bound.Port() == 0:
		return &ProtocolError{Stage: h.replyStage(), Field: wire.FieldPORT}
	case cmd == wire.CmdTorResolve && !bound.IP().IsValid(),
		cmd == wire.CmdTorResolvePTR && !bound.IsName():
		return &ProtocolError{Stage: wire.StageReply, Field: wire.FieldATYP, Got: byte(bound.ATYP())}
	}
	return nil
}

func (h *handshake) fail(err error) *HandshakeError { return &HandshakeError{h.readStage, err} }

// readNext reads at most the missing bytes plus ahead (the shortest messages
// sure to follow), so it never reads past the replies.
func (h *handshake) readNext(r io.Reader, stage string, ahead int, parse func([]byte) (int, error)) error {
	if h.mu != nil {
		h.mu.Lock()
		h.readStage = stage
		h.mu.Unlock()
	} else {
		h.readStage = stage
	}
	for {
		b := h.rbuf[h.msgStart:h.filled]
		n, err := parse(b)
		if err == nil {
			h.msgStart += min(max(n, 0), len(b))
			return nil
		}
		if !errors.Is(err, wire.ErrIncomplete) {
			return err
		}
		if h.readErr != nil {
			if errors.Is(h.readErr, io.EOF) || errors.Is(h.readErr, io.ErrUnexpectedEOF) {
				return &ProtocolError{Stage: stage, Err: io.ErrUnexpectedEOF}
			}
			return h.readErr
		}
		need := h.msgStart + max(n, len(b)+1) + ahead
		if need > len(h.rbuf) {
			if need > maxReplyBytes {
				return errLongAuth
			}
			h.rbuf = append(h.rbuf[:h.filled], make([]byte, need-h.filled)...)
		}
		m, err := r.Read(h.rbuf[h.filled:need])
		h.filled += m
		h.readErr = err
	}
}
