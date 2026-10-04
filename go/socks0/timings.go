package socks0

import (
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Timings records a Dialer's dial steps from its Trace hooks. Read it once the
// dial (ModeEarly: the handshake) returned. Reusable for sequential dials, not
// concurrent ones or a chain sharing the ctx.
type Timings struct {
	ProxyConnect time.Duration

	// Handshake is ConnectDone to the first GotReply, else HandshakeDone.
	Handshake time.Duration

	RelayDial time.Duration

	Total time.Duration

	start, connected, relay time.Time
	replied                 bool
	trace                   ClientTrace
}

// Trace returns hooks that fill t, the same ones on every call.
func (t *Timings) Trace() *ClientTrace {
	if t.trace.ConnectStart == nil {
		t.trace = ClientTrace{
			ConnectStart:   t.connectStart,
			ConnectDone:    t.connectDone,
			GotReply:       t.gotReply,
			HandshakeDone:  t.handshakeDone,
			RelayDialStart: t.relayDialStart,
			RelayDialDone:  t.relayDialDone,
		}
	}
	return &t.trace
}

func (t *Timings) connectStart(string, string) {
	t.ProxyConnect, t.Handshake, t.RelayDial, t.Total = 0, 0, 0, 0
	t.replied, t.connected, t.start = false, time.Time{}, time.Now()
}

func (t *Timings) connectDone(_, _ string, err error) {
	t.connected = time.Now()
	t.ProxyConnect = t.connected.Sub(t.start)
	if err != nil {
		t.Total = t.ProxyConnect
	}
}

func (t *Timings) gotReply(wire.Reply, wire.Addr) {
	if !t.replied && !t.connected.IsZero() {
		t.replied, t.Handshake = true, time.Since(t.connected)
	}
}

func (t *Timings) handshakeDone(error) {
	if t.connected.IsZero() { // a Client conn: no proxy dial
		return
	}
	now := time.Now()
	if !t.replied {
		t.Handshake = now.Sub(t.connected)
	}
	t.Total = now.Sub(t.start)
}

func (t *Timings) relayDialStart(string, string) { t.relay = time.Now() }

func (t *Timings) relayDialDone(string, string, error) { t.RelayDial = time.Since(t.relay) }
