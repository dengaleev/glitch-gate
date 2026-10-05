package server

import (
	"context"
	"net/netip"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// ServerTrace hooks (any may be nil) run synchronously and must not block, in the order
// GotGreeting < AuthDone < GotRequest < Replied < Done; Dropped runs on UDP relay goroutines.
// Hooks see raw client input (escape it before logging), never a password.
type ServerTrace struct {
	GotGreeting func(ctx context.Context, offered []wire.Method)                  // offered aliases a pooled buffer: copy what you keep
	AuthDone    func(ctx context.Context, m wire.Method, identity any, err error) // also for NoAuth
	GotRequest  func(ctx context.Context, r *Request)
	Replied     func(ctx context.Context, rep wire.Reply, bound wire.Addr, err error) // every reply sent, the server's own and ReplyListening's too
	Dropped     func(ctx context.Context, from netip.AddrPort, err error)             // a UDP datagram dropped, see AssociateHandler
	Done        func(ctx context.Context, r *Request, s ConnStats, err error)         // once per conn; r is nil before a request; err as ServeConn returns it
}

// ConnStats are payload bytes after the reply, as Conn counts them (also with splice, until NetConn).
type ConnStats struct {
	Received, Sent int64 // client→server, server→client
}

func (t *ServerTrace) gotGreeting(ctx context.Context, offered []wire.Method) {
	if t != nil && t.GotGreeting != nil {
		t.GotGreeting(ctx, offered)
	}
}

func (t *ServerTrace) authDone(ctx context.Context, m wire.Method, id any, err error) {
	if t != nil && t.AuthDone != nil {
		t.AuthDone(ctx, m, id, err)
	}
}

func (t *ServerTrace) gotRequest(ctx context.Context, r *Request) {
	if t != nil && t.GotRequest != nil {
		t.GotRequest(ctx, r)
	}
}

func (t *ServerTrace) replied(ctx context.Context, rep wire.Reply, bound wire.Addr, err error) {
	if t != nil && t.Replied != nil {
		t.Replied(ctx, rep, bound, err)
	}
}

func (t *ServerTrace) dropped(ctx context.Context, from netip.AddrPort, err error) {
	if t != nil && t.Dropped != nil {
		t.Dropped(ctx, from, err)
	}
}

func (t *ServerTrace) done(ctx context.Context, r *Request, s ConnStats, err error) {
	if t != nil && t.Done != nil {
		t.Done(ctx, r, s, err)
	}
}
