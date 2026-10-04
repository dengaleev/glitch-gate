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

type tracer [2]*ClientTrace

func newTracer(ctx context.Context, cfg *ClientTrace) tracer {
	return tracer{cfg, ContextClientTrace(ctx)}
}

func (t tracer) connectStart(network, addr string) {
	for _, h := range t {
		if h != nil && h.ConnectStart != nil {
			h.ConnectStart(network, addr)
		}
	}
}

func (t tracer) connectDone(network, addr string, err error) {
	for _, h := range t {
		if h != nil && h.ConnectDone != nil {
			h.ConnectDone(network, addr, err)
		}
	}
}

func (t tracer) wroteHandshake(err error) {
	for _, h := range t {
		if h != nil && h.WroteHandshake != nil {
			h.WroteHandshake(err)
		}
	}
}

func (t tracer) gotMethod(m wire.Method) {
	for _, h := range t {
		if h != nil && h.GotMethod != nil {
			h.GotMethod(m)
		}
	}
}

func (t tracer) authDone(err error) {
	for _, h := range t {
		if h != nil && h.AuthDone != nil {
			h.AuthDone(err)
		}
	}
}

func (t tracer) gotReply(rep wire.Reply, bound wire.Addr) {
	for _, h := range t {
		if h != nil && h.GotReply != nil {
			h.GotReply(rep, bound)
		}
	}
}

func (t tracer) handshakeDone(err error) {
	for _, h := range t {
		if h != nil && h.HandshakeDone != nil {
			h.HandshakeDone(err)
		}
	}
}

func (t tracer) relayDialStart(network, addr string) {
	for _, h := range t {
		if h != nil && h.RelayDialStart != nil {
			h.RelayDialStart(network, addr)
		}
	}
}

func (t tracer) relayDialDone(network, addr string, err error) {
	for _, h := range t {
		if h != nil && h.RelayDialDone != nil {
			h.RelayDialDone(network, addr, err)
		}
	}
}

func (t tracer) hasDroppedHook() bool {
	return t[0] != nil && t[0].DroppedDatagram != nil || t[1] != nil && t[1].DroppedDatagram != nil
}

func (t tracer) droppedDatagram(from wire.Addr, err error) {
	for _, h := range t {
		if h != nil && h.DroppedDatagram != nil {
			h.DroppedDatagram(from, err)
		}
	}
}

func (t tracer) accepted(peer wire.Addr, err error) {
	for _, h := range t {
		if h != nil && h.Accepted != nil {
			h.Accepted(peer, err)
		}
	}
}
