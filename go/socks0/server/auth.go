package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Authenticator is a SOCKS5 auth method shared by all conns: keep per-conn state on the stack.
type Authenticator interface {
	Method() wire.Method

	// Authenticate returns the identity, or, after queuing the failure message, an error matching
	// socks0.ErrAuthFailed; any other error closes the conn without sending what was queued. ctx
	// has the handshake deadline; c is invalid after return.
	Authenticate(ctx context.Context, c *AuthConn) (identity any, err error)
}

// AuthConn reads only whole messages through the server's buffer, so an Authenticator cannot
// consume pipelined bytes. Writes are queued and flushed before the next blocking read.
type AuthConn struct{ sc *serverConn }

// ReadMessage returns the next message, framed by parse per the wire Parse contract, reading only
// when parse asks for more (at most 1 KiB). The message aliases the buffer until the next call or
// Authenticate's return, when it is zeroed (best effort); kept longer it never shows another
// conn's bytes. After Authenticate returned it fails with net.ErrClosed.
func (c *AuthConn) ReadMessage(parse func(b []byte) (n int, err error)) ([]byte, error) {
	if c.sc != nil && c.sc.authenticating {
		c.sc.exposed = true
	}
	return c.readMessage(parse)
}

// readMessage keeps the buffer poolable: callers must keep no slice of the message.
func (c *AuthConn) readMessage(parse func(b []byte) (n int, err error)) ([]byte, error) {
	sc := c.sc
	if sc == nil || !sc.authenticating {
		return nil, net.ErrClosed
	}
	sc.clearLastMsg()
	msg, err := sc.next(socks0.StageAuth, maxAuthMsg, parse)
	if err != nil {
		return nil, err
	}
	sc.lastMsg = [2]int{sc.r - len(msg), sc.r}
	return msg, nil
}

// Write queues b, flushing beyond 1 KiB; errors surface at the next flush or ReadMessage. After
// Authenticate returned it fails with net.ErrClosed.
func (c *AuthConn) Write(b []byte) (int, error) {
	sc := c.sc
	if sc == nil || !sc.authenticating {
		return 0, net.ErrClosed
	}
	stage := socks0.StageAuth
	if sc.req.Method == wire.MethodUserPass {
		stage = wire.StageUserPassStatus
	}
	if len(sc.out)+len(b) > 2+maxAuthMsg {
		_ = sc.flush()
	}
	if len(b) > maxAuthMsg {
		if sc.writeErr == nil {
			sc.outStage = stage
			_, sc.writeErr = sc.nc.Write(b)
		}
		return len(b), nil
	}
	sc.queue(append(sc.out, b...), stage)
	return len(b), nil
}

func (c *AuthConn) LocalAddr() net.Addr {
	if c.sc == nil {
		return nil
	}
	return c.sc.nc.LocalAddr()
}

func (c *AuthConn) RemoteAddr() net.Addr {
	if c.sc == nil {
		return nil
	}
	return c.sc.nc.RemoteAddr()
}

type NoAuth struct{}

func (NoAuth) Method() wire.Method { return wire.MethodNoAuth }

func (NoAuth) Authenticate(context.Context, *AuthConn) (any, error) { return nil, nil }

// UserPass is RFC 1929 (cleartext: use TLS or trusted networks). A failure sends status 0x01 and
// an error matching socks0.ErrAuthFailed that never contains the password. There is no
// brute-force throttling: add it in Check or Server.Admit. fmt and slog show only the user count.
type UserPass struct {
	// Users maps user names to passwords; the identity is the name. Comparison is constant time over
	// fixed-size SHA-256 digests: neither password length nor user existence leaks.
	Users map[string]string

	// Check, if set, replaces Users; user and pass alias the buffer and are zeroed afterwards.
	Check func(ctx context.Context, user, pass []byte) (identity any, err error)
}

func (UserPass) Method() wire.Method { return wire.MethodUserPass }

func (a UserPass) Authenticate(ctx context.Context, c *AuthConn) (any, error) {
	msg, err := c.readMessage(parseUserPass)
	if err != nil {
		return nil, err
	}
	user, pass, _, _ := wire.ParseUserPass(msg)
	id, err := a.identify(ctx, c, user, pass)
	status := statusOK
	if err != nil {
		status = statusFailed
	}
	_, _ = c.Write(status[:])
	switch {
	case err == errRejected:
		return nil, err
	case err != nil:
		return nil, &rejectedError{err}
	}
	return id, nil
}

func (a UserPass) identify(ctx context.Context, c *AuthConn, user, pass []byte) (any, error) {
	switch {
	case a.Check != nil:
		c.sc.exposed = true
		return a.Check(ctx, user, pass)
	case a.verify(user, pass):
		return string(user), nil
	default:
		return nil, errRejected
	}
}

var (
	errRejected  = &socks0.AuthError{Method: wire.MethodUserPass, Status: 1}
	statusOK     = [2]byte{wire.UserPassVersion, 0}
	statusFailed = [2]byte{wire.UserPassVersion, 1}
)

type rejectedError struct{ err error }

func (e *rejectedError) Error() string   { return errRejected.Error() + ": " + e.err.Error() }
func (e *rejectedError) Unwrap() []error { return []error{errRejected, e.err} }

func (a UserPass) String() string {
	if a.Check != nil {
		return "server.UserPass(Check)"
	}
	return "server.UserPass(" + strconv.Itoa(len(a.Users)) + " users)"
}

func (a UserPass) GoString() string { return a.String() }

// Format writes String for every verb, so that none prints Users.
func (a UserPass) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

func (a UserPass) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("users", len(a.Users)), slog.Bool("check", a.Check != nil))
}

func parseUserPass(b []byte) (int, error) {
	_, _, n, err := wire.ParseUserPass(b)
	return n, err
}

func (a UserPass) verify(user, pass []byte) bool {
	want, ok := a.Users[string(user)]
	ok = ok && len(want) <= 255
	dg, dw := digest(pass), digest(want)
	eq := subtle.ConstantTimeCompare(dg[:], dw[:]) == 1
	clear(dg[:])
	clear(dw[:])
	return eq && ok
}

// digest hashes a length byte and p padded to 255 bytes: a fixed cost.
func digest[T ~string | ~[]byte](p T) [sha256.Size]byte {
	var b [256]byte
	b[0] = byte(len(p))
	copy(b[1:], p)
	d := sha256.Sum256(b[:])
	clear(b[:])
	return d
}
