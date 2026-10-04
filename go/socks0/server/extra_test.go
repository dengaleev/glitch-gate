package server_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func bindServer(h *server.BindHandler) *server.Server {
	s := open()
	s.Handler = h
	return s
}

func TestBindErrors(t *testing.T) {
	t.Run("accept timeout", func(t *testing.T) {
		s := bindServer(&server.BindHandler{AcceptTimeout: 100 * time.Millisecond, Filter: server.AllowAll})
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0")))
		expect(t, c, []byte{5, 0})
		readReply(t, c, wire.CmdBind)
		if rep, _ := readReply(t, c, wire.CmdBind); rep != wire.ReplyTTLExpired {
			t.Fatalf("second reply %v", rep)
		}
		if err := result(t, errc); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("client gone", func(t *testing.T) {
		s := bindServer(&server.BindHandler{Filter: server.AllowAll})
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0")))
		expect(t, c, []byte{5, 0})
		readReply(t, c, wire.CmdBind)
		c.Close()
		if err := result(t, errc); err == nil || !strings.Contains(err.Error(), "client closed") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unexpected and denied peers", func(t *testing.T) {
		// DST must be public to pass DefaultFilter; loopback peers then mismatch.
		s := bindServer(&server.BindHandler{AcceptTimeout: 300 * time.Millisecond})
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "8.8.8.8:0")))
		expect(t, c, []byte{5, 0})
		_, bound := readReply(t, c, wire.CmdBind)
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
	t.Run("unresolvable DST", func(t *testing.T) {
		s := bindServer(&server.BindHandler{})
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "nonexistent.invalid:0")))
		expect(t, c, []byte{5, 0})
		if rep, _ := readReply(t, c, wire.CmdBind); rep != wire.ReplyHostUnreachable {
			t.Fatalf("reply %v", rep)
		}
		_ = result(t, errc)
	})
	t.Run("ReplyListening twice", func(t *testing.T) {
		s := open()
		s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
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
		})
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0")))
		expect(t, c, []byte{5, 0})
		readReply(t, c, wire.CmdBind)
		if rep, _ := readReply(t, c, wire.CmdBind); rep != 5 {
			t.Fatal(rep)
		}
		_ = result(t, errc)
	})
}

// wrappedPC hides *net.UDPConn to force the relay's generic path.
type wrappedPC struct{ net.PacketConn }

func TestUDPGenericSockets(t *testing.T) {
	e := echoUDP(t, "127.0.0.1:0")
	var advertised netip.AddrPort
	h := &server.AssociateHandler{
		Filter: server.AllowAll,
		ListenClient: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			pc, err := net.ListenPacket(network, address)
			return wrappedPC{pc}, err
		},
		ListenTarget: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			pc, err := net.ListenPacket(network, address)
			return wrappedPC{pc}, err
		},
		Advertise: func(r *server.Request, relay netip.AddrPort) wire.Addr {
			advertised = relay
			return wire.AddrFromAddrPort(relay)
		},
	}
	proxy := serve(t, assocServer(h, nil))
	_, relay := assoc(t, proxy, "0.0.0.0:0")
	if advertised != relay.AddrPort() {
		t.Errorf("advertised %v, replied %v", advertised, relay)
	}
	c := udpSock(t)
	_, _ = c.WriteTo(dgram(apOf(e.LocalAddr()), "generic"), relay)
	if got := recv(c, 5*time.Second); !bytes.Equal(got, dgram(apOf(e.LocalAddr()), "generic")) {
		t.Fatalf("%x", got)
	}
}

func TestUDPIPv6(t *testing.T) {
	if !hasIPv6() {
		t.Skip("no IPv6 loopback")
	}
	e := echoUDP(t, "[::1]:0")
	s := assocServer(&server.AssociateHandler{Filter: server.AllowAll}, nil)
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	defer s.Close()
	_, relay := assoc(t, ln.Addr().String(), "[::]:0")
	if !relay.IP.Equal(net.IPv6loopback) {
		t.Fatalf("relay %v", relay)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.WriteTo(dgram(apOf(e.LocalAddr()), "v6"), relay)
	if got := recv(c, 5*time.Second); !bytes.Equal(got, dgram(apOf(e.LocalAddr()), "v6")) {
		t.Fatalf("%x", got)
	}
}

type lookupOnly struct{}

func (lookupOnly) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("::ffff:8.8.8.8")}, nil
}

func TestResolveEdges(t *testing.T) {
	for _, tt := range []struct {
		name string
		h    *server.ResolveHandler
		req  []byte
		rep  wire.Reply
		bnd  string
	}{
		{"F0 literal", &server.ResolveHandler{}, request(wire.CmdTorResolve, "8.8.4.4:0"), 0, "8.8.4.4:0"},
		{"F0 denied literal", &server.ResolveHandler{}, request(wire.CmdTorResolve, "10.1.1.1:0"), 2, ""},
		{"F0 mapped answer", &server.ResolveHandler{Resolver: lookupOnly{}}, request(wire.CmdTorResolve, "x.test:0"), 0, "8.8.8.8:0"},
		{"F1 without LookupAddr", &server.ResolveHandler{Resolver: lookupOnly{}}, request(wire.CmdTorResolvePTR, "8.8.8.8:0"), 7, ""},
		{"F1 of a name", &server.ResolveHandler{}, request(wire.CmdTorResolvePTR, "x.test:0"), 4, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := open()
			s.Handler = tt.h
			c, errc := serveOne(t, s)
			_, _ = c.Write(cat(greeting(0), tt.req))
			expect(t, c, []byte{5, 0})
			rep, bound, err := wire.ReadReply(c, wire.CmdTorResolve)
			if err != nil || rep != tt.rep || tt.bnd != "" && bound.String() != tt.bnd {
				t.Fatalf("%v %v %v", rep, bound, err)
			}
			_ = result(t, errc)
		})
	}
	s := open()
	s.Versions = server.V4
	s.Handler = &server.ResolveHandler{}
	c, errc := serveOne(t, s)
	req, _ := wire.AppendRequest4(nil, wire.CmdConnect, mustAddr("1.2.3.4:80"), "")
	_, _ = c.Write(req)
	if b := readN(t, c, 8); b[1] != 0x5B {
		t.Fatalf("%x", b)
	}
	_ = result(t, errc)
}

func TestMisc(t *testing.T) {
	if id, err := (server.NoAuth{}).Authenticate(context.Background(), nil); id != nil || err != nil {
		t.Error("NoAuth")
	}
	var ac server.AuthConn
	if ac.LocalAddr() != nil || ac.RemoteAddr() != nil {
		t.Error("zero AuthConn addresses")
	}
	var r server.Request
	if r.Early() != nil || r.ReplyListening(wire.Addr{}) == nil {
		t.Error("zero Request")
	}
	if _, err := r.Peek(context.Background(), 1); !errors.Is(err, server.ErrReplied) {
		t.Error(err)
	}
	s := open()
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			return err
		}
		if c.LocalAddr().String() != r.LocalAddr.String() || c.RemoteAddr().String() != r.RemoteAddr.String() ||
			c.SetDeadline(time.Time{}) != nil || c.SetReadDeadline(time.Time{}) != nil || c.SetWriteDeadline(time.Time{}) != nil {
			t.Error("Conn delegation")
		}
		if err := c.CloseRead(); err != nil {
			t.Error(err)
		}
		return nil
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
	expect(t, c, []byte{5, 0})
	readReply(t, c, wire.CmdConnect)
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
	errDB := errors.New("db down")
	s = open()
	s.Auth = []server.Authenticator{server.UserPass{Check: func(context.Context, []byte, []byte) (any, error) { return nil, errDB }}}
	c, errc = serveOne(t, s)
	_, _ = c.Write(cat(greeting(2), userPass("u", "p")))
	if err := result(t, errc); !strings.HasSuffix(err.Error(), "status 0x01): db down") || socks0.KindOf(err) != socks0.KindAuth {
		t.Fatalf("%v", err)
	}
}
