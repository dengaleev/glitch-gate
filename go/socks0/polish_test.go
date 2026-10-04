package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// offerProxy selects choose and reports the offered methods to got.
func offerProxy(choose wire.Method, got chan<- []wire.Method) func(net.Conn) {
	return func(c net.Conn) {
		methods, err := wire.ReadGreeting(c)
		if err != nil {
			return
		}
		got <- methods
		c.Write(wire.AppendMethodSelection(nil, choose))
		switch choose {
		case wire.MethodNoAuth:
		case wire.MethodUserPass:
			if _, _, err := wire.ReadUserPass(c); err != nil {
				return
			}
			c.Write(wire.AppendUserPassStatus(nil, 0))
		default:
			return
		}
		if _, _, err := wire.ReadRequest(c); err != nil {
			return
		}
		b, _ := wire.AppendReply(nil, wire.ReplySucceeded, defaultBound)
		c.Write(b)
		io.Copy(c, c)
	}
}

func TestOfferNoAuth(t *testing.T) {
	up := socks0.UserPass{Username: "u", Password: "p"}
	for _, tc := range []struct {
		name     string
		choose   wire.Method
		authDone bool
		is       error
		msg      string
	}{
		{name: "server takes no auth", choose: wire.MethodNoAuth},
		{name: "server takes user/pass", choose: wire.MethodUserPass, authDone: true},
		{name: "no acceptable", choose: wire.MethodNoAcceptable, is: socks0.ErrNoAcceptableMethods,
			msg: "socks method selection: no acceptable methods (offered username/password, no auth)"},
		{name: "not offered", choose: wire.MethodGSSAPI, is: socks0.ErrMethodNotOffered,
			msg: "socks method selection: server selected GSSAPI, offered username/password, no auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan []wire.Method, 1)
			var authDone bool
			d := &socks0.Dialer{ProxyAddr: listen(t, offerProxy(tc.choose, got)), Config: &socks0.Config{
				Mode: socks0.ModeSequential, Auth: up, OfferNoAuth: true,
				Trace: &socks0.ClientTrace{AuthDone: func(error) { authDone = true }},
			}}
			c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if m := <-got; !slices.Equal(m, []wire.Method{wire.MethodUserPass, wire.MethodNoAuth}) {
				t.Errorf("offered %v", m)
			}
			if tc.is != nil {
				me, ok := errors.AsType[*socks0.MethodError](err)
				if !ok || !errors.Is(err, tc.is) || !me.OfferedNoAuth || err.(*net.OpError).Err.Error() != tc.msg {
					t.Errorf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if authDone != tc.authDone {
				t.Errorf("AuthDone ran: %v", authDone)
			}
			c.Write([]byte("hi"))
			b := make([]byte, 2)
			if _, err := io.ReadFull(c, b); err != nil || string(b) != "hi" {
				t.Errorf("echo %q, %v", b, err)
			}
		})
	}

	// Config errors: never silently dropped.
	for _, cfg := range []socks0.Config{
		{Auth: up, OfferNoAuth: true},
		{Mode: socks0.ModeEarly, Auth: up, OfferNoAuth: true},
		{Mode: socks0.ModeSequential, Version: 4, OfferNoAuth: true},
		{Version: 4, Auth: socks0.UserPass{Username: "id"}, OfferNoAuth: true},
	} {
		d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t), Config: &cfg}
		if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.2:80"); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("%+v: %v", cfg, err)
		}
	}

	// With no Auth there is nothing to add: one method, as without it.
	mc := newMem([]byte{5, 0}, mustBinaryReply(t))
	c := socks0.Client(mc, "192.0.2.2:80", &socks0.Config{Mode: socks0.ModeSequential, OfferNoAuth: true})
	if err := c.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := mc.written(); !slices.Equal(w[:3], []byte{5, 1, 0}) {
		t.Errorf("greeting % x", w[:3])
	}
}

func mustBinaryReply(t *testing.T) []byte {
	b, err := wire.AppendReply(nil, wire.ReplySucceeded, defaultBound)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMethodErrorOfferedNoAuth(t *testing.T) {
	for _, tc := range []struct {
		err    *socks0.MethodError
		target error
		want   bool
	}{
		{&socks0.MethodError{Offered: 2, Selected: 0, OfferedNoAuth: true}, socks0.ErrMethodNotOffered, false},
		{&socks0.MethodError{Offered: 2, Selected: 0}, socks0.ErrMethodNotOffered, true},
		{&socks0.MethodError{Offered: 2, Selected: 1, OfferedNoAuth: true}, socks0.ErrMethodNotOffered, true},
		{&socks0.MethodError{Offered: 2, Selected: 0xFF, OfferedNoAuth: true}, socks0.ErrNoAcceptableMethods, true},
	} {
		if got := errors.Is(tc.err, tc.target); got != tc.want {
			t.Errorf("Is(%v, %v) = %v", tc.err, tc.target, got)
		}
	}
}

func TestListenUDP(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	u, err := d.ListenUDP(t.Context(), "udp4", "")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.WriteToAddr([]byte("hi"), wire.AddrFromAddrPort(echoAP)); err != nil {
		t.Fatal(err)
	}
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 8)
	n, from, err := u.ReadFromAddr(b)
	if err != nil || string(b[:n]) != "hi" || from != wire.AddrFromAddrPort(echoAP) {
		t.Errorf("ReadFromAddr = %q, %v, %v", b[:n], from, err)
	}

	if u, err := d.ListenUDP(t.Context(), "tcp", ""); u != nil || socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("ListenUDP tcp = %v, %v", u, err)
	}
	if pc, err := d.ListenPacket(t.Context(), "tcp", ""); pc != nil || err == nil {
		t.Errorf("ListenPacket tcp = %#v, %v", pc, err) // a nil interface, not a typed nil
	}
}

func TestIsProxyError(t *testing.T) {
	he := &socks0.HandshakeError{Stage: socks0.StageProxyDial, Err: errors.New("x")}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{io.EOF, false},
		{net.ErrClosed, false},
		{&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, false},
		{context.Canceled, false},
		{&net.OpError{Op: "socks connect", Net: "tcp", Err: he}, true},
		{fmt.Errorf("get: %w", &net.OpError{Op: "socks connect", Err: he}), true},
		{&net.OpError{Op: "read", Net: "udp", Err: fmt.Errorf("%w: %w", socks0.ErrAssociationClosed, io.EOF)}, true},
		{&socks0.ReplyError{Reply: wire.ReplyHostUnreachable}, true},
		{&socks0.MethodError{Selected: 0xFF}, true},
		{&socks0.AuthError{Status: 1}, true},
		{&socks0.ProtocolError{Stage: wire.StageReply}, true},
		{(*socks0.ReplyError)(nil), true},
	} {
		if got := socks0.IsProxyError(tc.err); got != tc.want {
			t.Errorf("IsProxyError(%v) = %v", tc.err, got)
		}
	}

	// From a real dial: refused proxy, REP 05; and plain I/O afterwards.
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy{rep: wire.ReplyConnectionRefused}.serve)}
	if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.2:80"); !socks0.IsProxyError(err) {
		t.Errorf("REP 05: %v", err)
	}
	d = &socks0.Dialer{ProxyAddr: listen(t, proxy{after: func(c net.Conn) {}}.serve)}
	c, err := d.DialContext(t.Context(), "tcp", "192.0.2.2:80")
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || socks0.IsProxyError(err) {
		t.Errorf("target EOF: %v", err)
	}
	c.Close()
}

func TestTimings(t *testing.T) {
	var tm socks0.Timings
	tr := tm.Trace()
	if tm.Trace() != tr {
		t.Error("Trace made new hooks")
	}
	slow := func(c net.Conn) { time.Sleep(20 * time.Millisecond); proxy{}.serve(c) }
	d := &socks0.Dialer{ProxyAddr: listen(t, slow), Config: &socks0.Config{Mode: socks0.ModeSequential}}
	c, err := d.DialContext(socks0.WithClientTrace(t.Context(), tr), "tcp", "192.0.2.2:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if tm.ProxyConnect <= 0 || tm.Handshake < 20*time.Millisecond || tm.RelayDial != 0 ||
		tm.Total < tm.ProxyConnect+tm.Handshake {
		t.Errorf("CONNECT: %+v", tm)
	}

	// Reused: a failed proxy dial resets the others.
	d = &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", Config: &socks0.Config{Trace: tr},
		ProxyDial: func(context.Context, string, string) (net.Conn, error) {
			time.Sleep(5 * time.Millisecond)
			return nil, errors.New("no route")
		}}
	if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.2:80"); err == nil {
		t.Fatal("no error")
	}
	if tm.ProxyConnect < 5*time.Millisecond || tm.Handshake != 0 || tm.Total != tm.ProxyConnect {
		t.Errorf("proxy dial failed: %+v", tm)
	}

	// A failure before any reply: Handshake runs to HandshakeDone.
	d = &socks0.Dialer{ProxyAddr: listen(t, scripted(nil, false)), Config: &socks0.Config{Trace: tr}}
	if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.2:80"); err == nil {
		t.Fatal("no error")
	}
	if tm.Handshake <= 0 || tm.Total < tm.ProxyConnect+tm.Handshake {
		t.Errorf("EOF: %+v", tm)
	}

	// UDP: the relay dial too.
	d = &socks0.Dialer{ProxyAddr: listenProxy(t), Config: &socks0.Config{Trace: tr}}
	u, err := d.ListenUDP(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	u.Close()
	if tm.RelayDial <= 0 || tm.Total < tm.ProxyConnect+tm.Handshake+tm.RelayDial {
		t.Errorf("UDP: %+v", tm)
	}

	// A Client conn has no proxy dial: nothing is timed, nothing panics.
	var tc socks0.Timings
	mc := newMem([]byte{5, 0}, mustBinaryReply(t))
	cc := socks0.Client(mc, "192.0.2.2:80", &socks0.Config{Trace: tc.Trace()})
	if err := cc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if tc.Handshake != 0 || tc.Total != 0 {
		t.Errorf("Client: %+v", tc)
	}
}

func TestUDPTraceOrder(t *testing.T) {
	var ev []string
	tr := &socks0.ClientTrace{
		GotReply:       func(wire.Reply, wire.Addr) { ev = append(ev, "GotReply") },
		RelayDialStart: func(string, string) { ev = append(ev, "RelayDialStart") },
		RelayDialDone:  func(_, _ string, err error) { ev = append(ev, fmt.Sprint("RelayDialDone ", err)) },
		HandshakeDone:  func(err error) { ev = append(ev, fmt.Sprint("HandshakeDone ", err)) },
	}
	d := &socks0.Dialer{ProxyAddr: listenProxy(t), Config: &socks0.Config{Trace: tr}}
	c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if want := []string{"GotReply", "RelayDialStart", "RelayDialDone <nil>", "HandshakeDone <nil>"}; !slices.Equal(ev, want) {
		t.Errorf("hooks %q, want %q", ev, want)
	}
}
