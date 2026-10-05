package server_test

// BIND: the two replies, the expected peer, and no name-existence oracle.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// bindRoundTrip has a peer connect to a BIND through d and exchanges data both ways.
func bindRoundTrip(t *testing.T, d *socks0.Dialer, expectPeer string) {
	t.Helper()
	ln, err := d.Listen(t.Context(), "tcp", expectPeer)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer := dial(t, ln.Addr().String())
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != peer.LocalAddr().String() {
		t.Errorf("peer %v, want %v", got, peer.LocalAddr())
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = peer.Write([]byte("from peer"))
	expect(t, c, []byte("from peer"))
	_, _ = c.Write([]byte("from client"))
	expect(t, peer, []byte("from client"))
}

func TestInteropBind(t *testing.T) {
	proxy := serve(t, withHandler(&server.Mux{Bind: &server.BindHandler{Filter: server.AllowAll}}))
	for _, m := range modes {
		for _, expectPeer := range []string{"127.0.0.1:0", "", "localhost:0"} {
			t.Run(m.String()+"/"+expectPeer, func(t *testing.T) {
				bindRoundTrip(t, &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Mode: m}}, expectPeer)
			})
		}
	}
}

// Data pipelined with the BIND request reaches the peer.
func TestBindEarlyData(t *testing.T) {
	proxy := serve(t, withHandler(&server.BindHandler{Filter: server.AllowAll}))
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0"), []byte("early to peer")))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdBind)
	peer := dial(t, bound.String())
	if rep, from := readReply(t, c, wire.CmdBind); rep != 0 || from.String() != peer.LocalAddr().String() {
		t.Fatalf("second reply %v %v", rep, from)
	}
	expect(t, peer, []byte("early to peer"))
}

func TestBindErrors(t *testing.T) {
	t.Run("accept timeout", func(t *testing.T) {
		c, _, _, errc := askOne(t, withHandler(&server.BindHandler{AcceptTimeout: 100 * time.Millisecond, Filter: server.AllowAll}), request(wire.CmdBind, "0.0.0.0:0"))
		if rep, _ := readReply(t, c, wire.CmdBind); rep != wire.ReplyTTLExpired {
			t.Fatalf("second reply %v", rep)
		}
		if err := result(t, errc); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("client gone", func(t *testing.T) {
		c, _, _, errc := askOne(t, withHandler(&server.BindHandler{Filter: server.AllowAll}), request(wire.CmdBind, "0.0.0.0:0"))
		c.Close()
		if err := result(t, errc); err == nil || !strings.Contains(err.Error(), "client closed") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unexpected and denied peers", func(t *testing.T) {
		// DST must be public to pass DefaultFilter; loopback peers then mismatch.
		c, _, bound, errc := askOne(t, withHandler(&server.BindHandler{AcceptTimeout: 300 * time.Millisecond}), request(wire.CmdBind, "8.8.8.8:0"))
		for range 2 {
			p, err := net.Dial("tcp", bound.String())
			if err != nil {
				t.Fatal(err)
			}
			_ = p.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := p.Read(make([]byte, 1)); err == nil {
				t.Fatal("unexpected peer kept")
			}
			p.Close()
		}
		if rep, _ := readReply(t, c, wire.CmdBind); rep != wire.ReplyTTLExpired {
			t.Fatalf("second reply %v", rep)
		}
		_ = result(t, errc)
	})
	t.Run("ReplyListening twice", func(t *testing.T) {
		c, errc := serveOne(t, withHandler(server.HandlerFunc(func(_ context.Context, r *server.Request) error {
			if err := r.ReplyListening(wire.Addr{}); err != nil {
				return err
			}
			if err := r.ReplyListening(wire.Addr{}); !errors.Is(err, server.ErrReplied) {
				t.Errorf("second ReplyListening: %v", err)
			}
			_, err := r.Reply(wire.ReplyConnectionRefused, wire.Addr{})
			if err := r.ReplyListening(wire.Addr{}); !errors.Is(err, server.ErrReplied) {
				t.Errorf("ReplyListening after Reply: %v", err)
			}
			return err
		})))
		_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0")))
		expect(t, c, []byte{5, 0})
		readReply(t, c, wire.CmdBind)
		if rep, _ := readReply(t, c, wire.CmdBind); rep != 5 {
			t.Fatal(rep)
		}
		_ = result(t, errc)
	})
}

// BIND, like CONNECT, replies 04 before listening for internal and unknown names alike, and 02
// for an internal literal.
func TestBindNoNameExistenceOracle(t *testing.T) {
	proxy := serve(t, withHandler(&server.Mux{
		Connect: &server.ConnectHandler{},
		Bind:    &server.BindHandler{AcceptTimeout: 5 * time.Second},
	}))
	first := func(cmd wire.Command, name string) wire.Reply {
		_, rep, _ := ask(t, proxy, rawRequest(cmd, name, 80))
		return rep
	}
	internal, unknown := "localhost", "no-such-host.invalid"
	ci, cu := first(wire.CmdConnect, internal), first(wire.CmdConnect, unknown)
	bi, bu := first(wire.CmdBind, internal), first(wire.CmdBind, unknown)
	if ci != cu || bi != bu || bi != wire.ReplyHostUnreachable {
		t.Fatalf("CONNECT internal %v / unknown %v; BIND internal %v / unknown %v: want all 04", ci, cu, bi, bu)
	}
	if _, rep, _ := ask(t, proxy, request(wire.CmdBind, "127.0.0.1:80")); rep != wire.ReplyNotAllowed {
		t.Fatalf("BIND 127.0.0.1: %v, want 02", rep)
	}
}
