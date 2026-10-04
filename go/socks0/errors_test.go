package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestErrorStrings(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want string
	}{
		{&socks0.ReplyError{Reply: wire.ReplyConnectionRefused}, "socks reply: connection refused"},
		{&socks0.ReplyError{Reply: 0x5b}, "socks reply: 0x5b"},
		{&socks0.MethodError{Offered: wire.MethodUserPass, Selected: wire.MethodNoAcceptable}, "socks method selection: no acceptable methods (offered username/password)"},
		{&socks0.MethodError{Offered: wire.MethodNoAuth, Selected: wire.MethodUserPass}, "socks method selection: server selected username/password, offered no auth"},
		{&socks0.MethodError{Offered: wire.MethodNoAuth, Selected: 0x42}, "socks method selection: server selected 0x42, offered no auth"},
		{&socks0.AuthError{Method: wire.MethodUserPass, Status: 1}, "socks auth: rejected (username/password status 0x01)"},
		{&socks0.HandshakeError{Stage: wire.StageReply, Err: &socks0.ReplyError{Reply: 1}}, "socks reply: general SOCKS server failure"},
		{&socks0.HandshakeError{Stage: wire.StageMethodSelection, Err: &socks0.MethodError{Selected: 0xFF}}, "socks method selection: no acceptable methods (offered no auth)"},
		{&socks0.HandshakeError{Stage: wire.StageUserPassStatus, Err: &socks0.AuthError{Method: 2, Status: 0xFF}}, "socks auth: rejected (username/password status 0xff)"},
		{&socks0.HandshakeError{Stage: wire.StageReply, Err: &socks0.ProtocolError{Stage: wire.StageReply, Field: wire.FieldATYP, Got: 9}}, "socks reply: invalid ATYP 0x09"},
		{&socks0.HandshakeError{Stage: wire.StageReply, Err: os.ErrDeadlineExceeded}, "socks reply: i/o timeout"},
		{&socks0.HandshakeError{Stage: socks0.StageConfig, Err: socks0.ErrNotPipelinable}, "socks config: socks0: authenticator cannot be pipelined"},
		{&socks0.HandshakeError{Stage: socks0.StageProxyDial}, "socks proxy dial: handshake failed"},
	} {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("%#v.Error() = %q, want %q", tt.err, got, tt.want)
		}
	}
}

type isTest struct {
	err    error
	target error
	want   bool
}

func rep(r wire.Reply) error { return &socks0.ReplyError{Reply: r} }

func TestErrorIs(t *testing.T) {
	tests := append([]isTest{
		{rep(7), errors.ErrUnsupported, true},
		{rep(5), errors.ErrUnsupported, false},
		{&socks0.MethodError{Offered: 0, Selected: 0xFF}, socks0.ErrNoAcceptableMethods, true},
		{&socks0.MethodError{Offered: 0, Selected: 0xFF}, socks0.ErrMethodNotOffered, false},
		{&socks0.MethodError{Offered: 0, Selected: 2}, socks0.ErrMethodNotOffered, true},
		{&socks0.MethodError{Offered: 0, Selected: 2}, socks0.ErrNoAcceptableMethods, false},
		{&socks0.MethodError{Offered: 2, Selected: 2}, socks0.ErrMethodNotOffered, false},
		{&socks0.MethodError{}, socks0.ErrAuthFailed, false},
		{&socks0.AuthError{}, socks0.ErrAuthFailed, true},
		{&socks0.AuthError{}, socks0.ErrNoAcceptableMethods, false},
		{rep(wire.ReplyNotAllowed), socks0.ErrNotAllowed, true},
		{rep(wire.ReplyGeneralFailure), socks0.ErrNotAllowed, false},
		{&socks0.ReplyError{Reply: wire.ReplyNotAllowed, Version: 4}, socks0.ErrNotAllowed, false},
	}, errnoIsTests()...)
	for _, tt := range tests {
		if got := errors.Is(tt.err, tt.target); got != tt.want {
			t.Errorf("Is(%v, %v) = %v", tt.err, tt.target, got)
		}
	}
	// REP 06 matches ETIMEDOUT but is no timeout: the proxy answered.
	err := &net.OpError{Op: "socks connect", Err: &socks0.HandshakeError{Stage: wire.StageReply, Err: rep(6)}}
	if err.Timeout() || socks0.KindOf(err) != socks0.KindReply {
		t.Errorf("REP 06: Timeout %v, kind %v", err.Timeout(), socks0.KindOf(err))
	}
}

func TestHandshakeErrorUnwrap(t *testing.T) {
	he := &socks0.HandshakeError{Stage: wire.StageReply, Err: context.DeadlineExceeded}
	op := &net.OpError{Op: "socks connect", Err: he}
	if !op.Timeout() || !he.Timeout() || errors.Unwrap(he) != context.DeadlineExceeded {
		t.Error("deadline")
	}
	if (&socks0.HandshakeError{Err: io.EOF}).Timeout() || (&socks0.HandshakeError{}).Timeout() {
		t.Error("not timeouts")
	}
	if got, ok := errors.AsType[*socks0.HandshakeError](op); !ok || got != he {
		t.Error("AsType")
	}
}

type timeoutErr struct{ timeout bool }

func (e timeoutErr) Error() string { return fmt.Sprint("timeout ", e.timeout) }
func (e timeoutErr) Timeout() bool { return e.timeout }

type netErr struct{}

func (netErr) Error() string   { return "net" }
func (netErr) Timeout() bool   { return false }
func (netErr) Temporary() bool { return false }

type kindTest struct {
	err  error
	want socks0.Kind
}

func hs(stage string, err error) error {
	return &net.OpError{Op: "socks connect", Net: "tcp", Err: &socks0.HandshakeError{Stage: stage, Err: err}}
}

func TestKindOf(t *testing.T) {
	tests := []kindTest{
		{nil, ""},
		{hs(socks0.StageConfig, errTest), socks0.KindConfig},
		{socks0.ErrNotPipelinable, socks0.KindConfig},
		{fmt.Errorf("x: %w", wire.ErrInvalid), socks0.KindConfig},
		{hs(wire.StageReply, &socks0.ReplyError{Reply: 5}), socks0.KindReply},
		{hs(wire.StageMethodSelection, &socks0.MethodError{Selected: 0xFF}), socks0.KindMethod},
		{hs(wire.StageUserPassStatus, &socks0.AuthError{}), socks0.KindAuth},
		{hs(socks0.StageAuth, errors.Join(socks0.ErrAuthFailed, errTest)), socks0.KindAuth},
		{hs(wire.StageReply, &socks0.ProtocolError{Stage: wire.StageReply, Field: wire.FieldVER}), socks0.KindProtocol},
		{hs(wire.StageReply, &socks0.ProtocolError{Stage: wire.StageReply, Err: io.ErrUnexpectedEOF}), socks0.KindEOF},
		{hs(wire.StageReply, context.Canceled), socks0.KindCanceled},
		{hs(wire.StageReply, net.ErrClosed), socks0.KindClosed},
		{hs(socks0.StageResolve, &net.DNSError{Err: "no such host", IsNotFound: true}), socks0.KindDNS},
		{hs(wire.StageReply, context.DeadlineExceeded), socks0.KindTimeout},
		{hs(wire.StageReply, os.ErrDeadlineExceeded), socks0.KindTimeout},
		{errors.Join(errTest, timeoutErr{true}), socks0.KindTimeout},
		{errors.Join(errTest, timeoutErr{false}), socks0.KindOther},
		{hs(wire.StageReply, io.EOF), socks0.KindEOF},
		{io.ErrUnexpectedEOF, socks0.KindEOF},
		{hs(wire.StageReply, netErr{}), socks0.KindNetwork},
		{errTest, socks0.KindOther},
		// Amendments for the server (DESIGN.md §4).
		{hs(wire.StageReply, rep(wire.ReplyNotAllowed)), socks0.KindReply},
		{fmt.Errorf("dial: %w", socks0.ErrNotAllowed), socks0.KindDenied},
		{errors.Join(socks0.ErrNotAllowed, context.Canceled), socks0.KindDenied},
		{fmt.Errorf("greeting: %w", socks0.ErrNoAcceptableMethods), socks0.KindMethod},
	}
	tests = append(tests, errnoKindTests()...)
	for _, tt := range tests {
		if got := socks0.KindOf(tt.err); got != tt.want {
			t.Errorf("KindOf(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}
