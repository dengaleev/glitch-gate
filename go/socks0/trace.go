package socks0

import (
	"context"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// ClientTrace holds hooks, as in net/http/httptrace; any may be nil. Hooks run
// synchronously and must not block, in field order except that RelayDial*
// precede HandshakeDone (in ModeEarly possibly concurrently). HandshakeDone
// runs iff WroteHandshake ran, last, with the caller's error.
type ClientTrace struct {
	ConnectStart func(network, addr string)
	ConnectDone  func(network, addr string, err error)

	// WroteHandshake follows the first handshake write (ModeSequential: greeting).
	WroteHandshake func(err error)

	GotMethod func(m wire.Method)

	// AuthDone is not called for MethodNoAuth or a failed method selection.
	AuthDone func(err error)

	// GotReply runs per reply with valid VER and REP; bound is zero if a REP ≠ 0
	// reply's tail is malformed.
	GotReply func(rep wire.Reply, bound wire.Addr)

	// HandshakeDone runs once; for UDP ASSOCIATE after the relay dial.
	HandshakeDone func(err error)

	// RelayDialStart and RelayDialDone get the address after BND substitution.
	RelayDialStart func(network, addr string)
	RelayDialDone  func(network, addr string, err error)

	// DroppedDatagram's err is a *ProtocolError (from zero), ErrFragment or
	// ErrWrongSource.
	DroppedDatagram func(from wire.Addr, err error)

	Accepted func(peer wire.Addr, err error)
}

type traceKey struct{}

// WithClientTrace returns a ctx whose hooks run trace's before those already
// in ctx. A Client conn sees it only via the HandshakeContext that starts the
// handshake; implicit handshakes see only Config.Trace.
func WithClientTrace(ctx context.Context, trace *ClientTrace) context.Context {
	if trace == nil {
		return ctx
	}
	if old := ContextClientTrace(ctx); old != nil {
		trace = compose(trace, old)
	}
	return context.WithValue(ctx, traceKey{}, trace)
}

func ContextClientTrace(ctx context.Context) *ClientTrace {
	t, _ := ctx.Value(traceKey{}).(*ClientTrace)
	return t
}

func compose(a, b *ClientTrace) *ClientTrace {
	return &ClientTrace{
		ConnectStart:    join2(a.ConnectStart, b.ConnectStart),
		ConnectDone:     join3(a.ConnectDone, b.ConnectDone),
		WroteHandshake:  join1(a.WroteHandshake, b.WroteHandshake),
		GotMethod:       join1(a.GotMethod, b.GotMethod),
		AuthDone:        join1(a.AuthDone, b.AuthDone),
		GotReply:        join2(a.GotReply, b.GotReply),
		HandshakeDone:   join1(a.HandshakeDone, b.HandshakeDone),
		RelayDialStart:  join2(a.RelayDialStart, b.RelayDialStart),
		RelayDialDone:   join3(a.RelayDialDone, b.RelayDialDone),
		DroppedDatagram: join2(a.DroppedDatagram, b.DroppedDatagram),
		Accepted:        join2(a.Accepted, b.Accepted),
	}
}

func join1[A any](f, g func(A)) func(A) {
	switch {
	case f == nil:
		return g
	case g == nil:
		return f
	}
	return func(a A) { f(a); g(a) }
}

func join2[A, B any](f, g func(A, B)) func(A, B) {
	switch {
	case f == nil:
		return g
	case g == nil:
		return f
	}
	return func(a A, b B) { f(a, b); g(a, b) }
}

func join3[A, B, C any](f, g func(A, B, C)) func(A, B, C) {
	switch {
	case f == nil:
		return g
	case g == nil:
		return f
	}
	return func(a A, b B, c C) { f(a, b, c); g(a, b, c) }
}

// noTrace runs no hooks; newTracer returns it, never nil, so a Conn's trace
// is nil only until chosen.
var noTrace = new(ClientTrace)

// newTracer returns cfg's hooks, then ctx's.
func newTracer(ctx context.Context, cfg *ClientTrace) *ClientTrace {
	t := ContextClientTrace(ctx)
	switch {
	case cfg == nil && t == nil:
		return noTrace
	case t == nil:
		return cfg
	case cfg == nil:
		return t
	}
	return compose(cfg, t)
}

// The hook runners take a nil t.

func (t *ClientTrace) connectStart(network, addr string) {
	if t != nil && t.ConnectStart != nil {
		t.ConnectStart(network, addr)
	}
}

func (t *ClientTrace) connectDone(network, addr string, err error) {
	if t != nil && t.ConnectDone != nil {
		t.ConnectDone(network, addr, err)
	}
}

func (t *ClientTrace) wroteHandshake(err error) {
	if t != nil && t.WroteHandshake != nil {
		t.WroteHandshake(err)
	}
}

func (t *ClientTrace) gotMethod(m wire.Method) {
	if t != nil && t.GotMethod != nil {
		t.GotMethod(m)
	}
}

func (t *ClientTrace) authDone(err error) {
	if t != nil && t.AuthDone != nil {
		t.AuthDone(err)
	}
}

func (t *ClientTrace) gotReply(rep wire.Reply, bound wire.Addr) {
	if t != nil && t.GotReply != nil {
		t.GotReply(rep, bound)
	}
}

func (t *ClientTrace) handshakeDone(err error) {
	if t != nil && t.HandshakeDone != nil {
		t.HandshakeDone(err)
	}
}

func (t *ClientTrace) relayDialStart(network, addr string) {
	if t != nil && t.RelayDialStart != nil {
		t.RelayDialStart(network, addr)
	}
}

func (t *ClientTrace) relayDialDone(network, addr string, err error) {
	if t != nil && t.RelayDialDone != nil {
		t.RelayDialDone(network, addr, err)
	}
}

func (t *ClientTrace) hasDroppedHook() bool { return t != nil && t.DroppedDatagram != nil }

func (t *ClientTrace) droppedDatagram(from wire.Addr, err error) {
	if t.hasDroppedHook() {
		t.DroppedDatagram(from, err)
	}
}

func (t *ClientTrace) accepted(peer wire.Addr, err error) {
	if t != nil && t.Accepted != nil {
		t.Accepted(peer, err)
	}
}
