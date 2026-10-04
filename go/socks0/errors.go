package socks0

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/dengaleev/glitch-gate/go/socks0/internal/errno"
	"github.com/dengaleev/glitch-gate/go/socks0/internal/neterr"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	// ErrAuthFailed is matched by *AuthError and custom Authenticators' rejections.
	ErrAuthFailed = errors.New("socks0: authentication failed")

	ErrNoAcceptableMethods = errors.New("socks0: no acceptable methods")

	ErrMethodNotOffered = errors.New("socks0: server selected a method not offered")

	// ErrNotAllowed is matched by REP 02, a refused UDP relay address and server
	// policy denials.
	ErrNotAllowed = errors.New("socks0: not allowed")

	// ErrNotPipelinable: Auth is not a Pipeliner outside ModeSequential.
	ErrNotPipelinable = errors.New("socks0: authenticator cannot be pipelined")

	// ErrAssociationClosed is matched by UDPConn errors once the proxy ended the
	// association; the control conn's error is wrapped too.
	ErrAssociationClosed = errors.New("socks0: UDP association closed by proxy")

	// ErrFragment and ErrWrongSource are only passed to ClientTrace.DroppedDatagram.
	ErrFragment    = errors.New("socks0: fragmented datagram dropped")
	ErrWrongSource = errors.New("socks0: datagram from another source dropped")
)

// Values of HandshakeError.Stage besides the wire.Stage* message stages.
const (
	StageConfig    = "config"     // before connecting: bad arguments or Config
	StageResolve   = "resolve"    // Dialer.Resolver looking up the target
	StageProxyDial = "proxy dial" // ProxyDial
	StageAuth      = "auth"       // a custom Authenticator's subnegotiation
	StageRelayDial = "relay dial" // UDP: BND substitution and RelayDial or RelayListen
	StageAccept    = "accept"     // BIND: awaiting the second reply
)

// HandshakeError is the Err of every *net.OpError of a failed handshake.
// Stage is the first message not fully written, or (reads, timeouts,
// cancellation) not fully received. In ModePipelined a timeout at
// wire.StageReply proves the server is alive and holds the request.
type HandshakeError struct {
	Stage string // a Stage* constant or a wire.Stage* constant
	Err   error
}

// Error holds no addresses, so it suits metrics labels.
func (e *HandshakeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	stage := e.Stage
	if !strings.HasPrefix(stage, "socks4 ") {
		stage = "socks " + stage
	}
	switch {
	case e.Err == nil:
		return stage + ": handshake failed"
	case serverMsg(e.Err, false):
		return e.Err.Error()
	}
	return stage + ": " + e.Err.Error()
}

func (e *HandshakeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *HandshakeError) Timeout() bool {
	return e != nil && neterr.IsTimeout(e.Err)
}

// ReplyError is a non-success REP (SOCKS4: CD), returned even if the rest of
// the reply is malformed (Bound zero). REP 02 matches ErrNotAllowed, 07
// errors.ErrUnsupported, and (not plan9) 03–06 ENETUNREACH, EHOSTUNREACH,
// ECONNREFUSED, ETIMEDOUT; never a net.Error timeout. SOCKS4 0x5C/0x5D match
// ErrAuthFailed.
type ReplyError struct {
	Reply   wire.Reply
	Bound   wire.Addr // BND as sent, often 0.0.0.0:0
	Version uint8     // 4 for SOCKS4; 5 (or 0) for SOCKS5
}

func (e *ReplyError) Error() string {
	switch {
	case e == nil:
		return "<nil>"
	case e.Version == 4:
		return "socks4 reply: " + wire.Reply4String(e.Reply)
	}
	return "socks reply: " + e.Reply.String()
}

func (e *ReplyError) Is(target error) bool {
	switch {
	case e == nil:
		return false
	case e.Version == 4:
		return target == ErrAuthFailed && (e.Reply == wire.Reply4NoIdentd || e.Reply == wire.Reply4IdentMismatch)
	case target == errors.ErrUnsupported:
		return e.Reply == wire.ReplyCommandNotSupported
	case target == ErrNotAllowed:
		return e.Reply == wire.ReplyNotAllowed
	}
	return errno.Is(e.Reply, target)
}

// MethodError is a method selection the client cannot use.
type MethodError struct {
	Offered       wire.Method // Config.Auth's method, or MethodNoAuth
	Selected      wire.Method
	OfferedNoAuth bool // Config.OfferNoAuth
}

func (e *MethodError) Error() string {
	if e == nil {
		return "<nil>"
	}
	offered := e.Offered.String()
	if e.OfferedNoAuth {
		offered += ", " + wire.MethodNoAuth.String()
	}
	if e.Selected == wire.MethodNoAcceptable {
		return "socks method selection: no acceptable methods (offered " + offered + ")"
	}
	return "socks method selection: server selected " + e.Selected.String() + ", offered " + offered
}

func (e *MethodError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrNoAcceptableMethods:
		return e.Selected == wire.MethodNoAcceptable
	case ErrMethodNotOffered:
		return e.Selected != wire.MethodNoAcceptable && e.Selected != e.Offered &&
			(!e.OfferedNoAuth || e.Selected != wire.MethodNoAuth)
	}
	return false
}

// AuthError is a rejection; for MethodUserPass, Status is RFC 1929's.
type AuthError struct {
	Method wire.Method
	Status uint8
}

func (e *AuthError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("socks auth: rejected (%s status 0x%02x)", e.Method, e.Status)
}

func (e *AuthError) Is(target error) bool { return target == ErrAuthFailed }

// ProtocolError is a malformed or truncated server message.
type ProtocolError = wire.ProtocolError

// Kind classifies a socks0 error for metrics; stable within a major version.
type Kind string

const (
	KindConfig      Kind = "config"      // invalid argument or Config; nothing sent
	KindCanceled    Kind = "canceled"    // ctx canceled
	KindTimeout     Kind = "timeout"     // deadline, ctx deadline, ReplyTimeout
	KindRefused     Kind = "refused"     // ECONNREFUSED from the proxy (not REP 05)
	KindReset       Kind = "reset"       // ECONNRESET, ECONNABORTED, EPIPE
	KindEOF         Kind = "eof"         // proxy closed mid-handshake
	KindUnreachable Kind = "unreachable" // local ENETUNREACH/EHOSTUNREACH
	KindDNS         Kind = "dns"         // resolving the proxy or (Resolver) the target
	KindNetwork     Kind = "network"     // other transport error
	KindProtocol    Kind = "protocol"    // malformed server message
	KindMethod      Kind = "method"      // *MethodError
	KindAuth        Kind = "auth"        // matches ErrAuthFailed
	KindReply       Kind = "reply"       // *ReplyError (code via errors.As)
	KindClosed      Kind = "closed"      // net.ErrClosed (local Close)
	KindAssociation Kind = "association" // ErrAssociationClosed
	KindDenied      Kind = "denied"      // ErrNotAllowed: a server policy denial; REP 02 stays KindReply
	KindOther       Kind = "other"
)

// KindOf classifies err ("" for nil); the first match wins: association,
// config, resolve (canceled or dns), reply, method, auth, protocol (eof if
// truncated), denied, canceled, closed, dns, timeout, refused, reset,
// unreachable, eof, network, other. So REP 05 is KindReply, not KindRefused.
func KindOf(err error) Kind {
	if err == nil {
		return ""
	}
	he, _ := errors.AsType[*HandshakeError](err)
	if k := socksKind(err, he); k != "" {
		return k
	}
	return transportKind(err, he)
}

func socksKind(err error, he *HandshakeError) Kind {
	switch {
	case errors.Is(err, ErrAssociationClosed):
		return KindAssociation
	case he != nil && he.Stage == StageConfig, isConfigErr(err):
		return KindConfig
	case he != nil && he.Stage == StageResolve: // never the RESOLVE's own reply
		if errors.Is(err, context.Canceled) {
			return KindCanceled
		}
		return KindDNS
	case hasErrType[*ReplyError](err):
		return KindReply
	case hasErrType[*MethodError](err), errors.Is(err, ErrNoAcceptableMethods):
		return KindMethod
	case errors.Is(err, ErrAuthFailed):
		return KindAuth
	case hasErrType[*ProtocolError](err):
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return KindEOF
		}
		return KindProtocol
	case errors.Is(err, ErrNotAllowed):
		return KindDenied
	}
	return ""
}

func isConfigErr(err error) bool {
	return errors.Is(err, ErrNotPipelinable) || errors.Is(err, wire.ErrInvalid) || errors.Is(err, errFastOpen)
}

func transportKind(err error, he *HandshakeError) Kind {
	switch {
	case errors.Is(err, context.Canceled):
		return KindCanceled
	case errors.Is(err, net.ErrClosed):
		return KindClosed
	case hasErrType[*net.DNSError](err):
		return KindDNS
	case neterr.IsTimeout(err):
		return KindTimeout
	}
	if k := errnoKind(err); k != "" {
		return k
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return KindEOF
	}
	if he != nil {
		err = he.Err // skip socks0's own *net.OpError
	}
	if hasErrType[net.Error](err) {
		return KindNetwork
	}
	return KindOther
}

func hasErrType[T error](err error) bool {
	_, ok := errors.AsType[T](err)
	return ok
}

// serverMsg reports a server message error (*ReplyError, *MethodError,
// *AuthError, *ProtocolError): err itself or, if deep, any in its tree.
func serverMsg(err error, deep bool) bool {
	return isErrType[*ReplyError](err, deep) || isErrType[*MethodError](err, deep) ||
		isErrType[*AuthError](err, deep) || isErrType[*ProtocolError](err, deep)
}

func isErrType[T error](err error, deep bool) bool {
	if deep {
		return hasErrType[T](err)
	}
	_, ok := err.(T)
	return ok
}

// isServerMsgErr: a local deadline or cancellation cannot have caused err.
func isServerMsgErr(err error) bool {
	return serverMsg(err, false) || errors.Is(err, ErrAuthFailed)
}

// IsProxyError reports a SOCKS-layer failure (a *HandshakeError,
// ErrAssociationClosed, or a server message error), not a traffic one: for
// an http.Client, true if the proxy leg failed, false if the target did.
func IsProxyError(err error) bool {
	switch {
	case err == nil:
		return false
	case hasErrType[*HandshakeError](err), errors.Is(err, ErrAssociationClosed):
		return true
	}
	return serverMsg(err, true)
}
