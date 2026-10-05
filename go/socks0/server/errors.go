package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/internal/neterr"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	// ErrServerClosed is returned after Shutdown or Close.
	ErrServerClosed = errors.New("socks0/server: Server closed")

	// ErrReplied is returned by Reply, ReplyListening and Peek after a reply or ServeSOCKS's return.
	ErrReplied = errors.New("socks0/server: already replied")

	// ErrNoReply is ServeConn's error when the handler returned nil without replying (01 was sent).
	ErrNoReply = errors.New("socks0/server: handler returned without replying")

	// ErrNotAllowed is matched by every policy denial; ReplyFor maps it to 02.
	ErrNotAllowed = socks0.ErrNotAllowed
)

// Reasons passed to ServerTrace.Dropped for UDP datagrams; never returned.
var (
	ErrFragment       = errors.New("socks0/server: fragmented datagram dropped")
	ErrWrongSource    = errors.New("socks0/server: datagram from another source")
	ErrUnsolicited    = errors.New("socks0/server: unsolicited datagram from target")
	ErrTooLarge       = errors.New("socks0/server: datagram over MaxDatagram")
	ErrTooManyTargets = errors.New("socks0/server: association over MaxTargets")
)

var (
	errUnsupported = fmt.Errorf("socks0/server: %w", errors.ErrUnsupported)
	errTooLong     = errors.New("message over 1 KiB")
	errContract    = errors.New("parse broke the wire Parse contract")
	errSOCKS4Auth  = fmt.Errorf("%w: SOCKS4 needs Server.UserID, or the built-in NoAuth in Server.Auth", socks0.ErrAuthFailed)
	errSOCKS4Cmd   = fmt.Errorf("socks0/server: SOCKS4 command: %w", errors.ErrUnsupported)
	errClientGone  = errors.New("socks0/server: client closed during BIND")
)

// DeniedError is a target denied by a Filter; its message holds no address.
type DeniedError struct {
	Addr   netip.AddrPort // unmapped, without zone
	Reason string         // "loopback", "private", "cgnat", "link-local", "metadata", "own address", "multicast", "reserved", "port 0", …
}

func (e *DeniedError) Error() string { return "socks target denied: " + e.Reason }

func (e *DeniedError) Is(target error) bool { return target == ErrNotAllowed }

type MethodError struct{ Offered []wire.Method }

func (e *MethodError) Error() string {
	names := make([]string, len(e.Offered))
	for i, m := range e.Offered {
		names[i] = m.String()
	}
	return "socks greeting: no acceptable methods (offered " + strings.Join(names, ", ") + ")"
}

// Is matches socks0.ErrNoAcceptableMethods.
func (e *MethodError) Is(target error) bool { return target == socks0.ErrNoAcceptableMethods }

// ReplyFor maps an error to the REP sent for it; the first match wins (no errno rows on plan9):
//
//	nil                                      00
//	*socks0.ReplyError (an upstream's)       its REP (SOCKS4 5B → 01, 5C/5D → 02)
//	ErrNotAllowed, EACCES, EPERM             02
//	errors.ErrUnsupported                    07
//	ENETUNREACH                              03
//	EHOSTUNREACH, *net.DNSError              04
//	ECONNREFUSED                             05
//	a timeout, context.DeadlineExceeded      06
//	anything else (context.Canceled too)     01
func ReplyFor(err error) wire.Reply {
	if err == nil {
		return wire.ReplySucceeded
	}
	if re, ok := errors.AsType[*socks0.ReplyError](err); ok && re != nil {
		return upstreamReply(re)
	}
	switch {
	case errors.Is(err, ErrNotAllowed):
		return wire.ReplyNotAllowed
	case errors.Is(err, errors.ErrUnsupported):
		return wire.ReplyCommandNotSupported
	}
	if rep, ok := errnoReply(err); ok {
		return rep
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return wire.ReplyHostUnreachable
	}
	if neterr.IsTimeout(err) { // context.DeadlineExceeded too
		return wire.ReplyTTLExpired
	}
	return wire.ReplyGeneralFailure
}

func upstreamReply(re *socks0.ReplyError) wire.Reply {
	switch {
	case re.Version != 4:
		return re.Reply
	case re.Reply == wire.Reply4NoIdentd, re.Reply == wire.Reply4IdentMismatch:
		return wire.ReplyNotAllowed
	}
	return wire.ReplyGeneralFailure
}

type panicError struct {
	value   string
	replied bool
}

func (e *panicError) Error() string { return "socks0/server: handler panic: " + e.value }

// Is matches ErrNoReply if the panic came before a reply.
func (e *panicError) Is(target error) bool { return target == ErrNoReply && !e.replied }
