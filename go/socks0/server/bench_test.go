package server_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// memConn replays script then EOF, discards writes, allocates nothing.
type memConn struct {
	script []byte
	off    int
}

var (
	memLocal  = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
	memRemote = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
)

func (c *memConn) Read(b []byte) (int, error) {
	if c.off == len(c.script) {
		return 0, io.EOF
	}
	n := copy(b, c.script[c.off:])
	c.off += n
	return n, nil
}

func (c *memConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *memConn) Close() error                     { return nil }
func (c *memConn) LocalAddr() net.Addr              { return memLocal }
func (c *memConn) RemoteAddr() net.Addr             { return memRemote }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

// handshakeAllocs counts the server's own allocations, no network stack.
func handshakeAllocs(t testing.TB, s *server.Server, script []byte) float64 {
	c := &memConn{script: script}
	ctx := context.Background()
	if err := s.ServeConn(ctx, c); err != nil {
		t.Fatal(err)
	}
	return testing.AllocsPerRun(200, func() {
		c.off = 0
		_ = s.ServeConn(ctx, c)
	})
}

func replyHandler() server.HandlerFunc {
	return func(_ context.Context, r *server.Request) error {
		c, err := r.Reply(0, wire.AddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:1234")))
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, c)
		return nil
	}
}

func memDial(context.Context, string, string) (net.Conn, error) { return &memConn{}, nil }

// Allocation budget per conn (DESIGN.md §4); Relay costs a fixed amount per tunnel, none per byte.
func TestAllocBudget(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates; budgets are checked without -race")
	}
	ip := cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), []byte("early"))
	name := cat(greeting(0), request(wire.CmdConnect, "example.com:80"))
	up := cat(greeting(2), userPass("u", "p"), request(wire.CmdConnect, "192.0.2.1:80"))
	for _, tt := range []struct {
		name   string
		s      *server.Server
		script []byte
		budget float64
	}{
		// serverConn + its ctx (2)
		{"handshake+reply", &server.Server{Handler: replyHandler()}, ip, 3},
		// + the name string
		{"handshake+reply/name", &server.Server{Handler: replyHandler()}, name, 4},
		// + the boxed identity string
		{"handshake+reply/userpass", &server.Server{Handler: replyHandler(), Auth: []server.Authenticator{server.UserPass{Users: map[string]string{"u": "p"}}}}, up, 5},
		// + dial address, Filter closure, Relay state and goroutine, memDial's target
		{"CONNECT incl. relay", &server.Server{Handler: &server.ConnectHandler{Dial: memDial, DialTimeout: -1}}, ip, 9 + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := handshakeAllocs(t, tt.s, tt.script)
			t.Logf("%.0f allocs", n)
			if n > tt.budget {
				t.Errorf("%.0f allocs, budget %.0f", n, tt.budget)
			}
		})
	}

	// A ctx other than the handler's costs a context.AfterFunc.
	c1, c2 := &memConn{}, &memConn{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := testing.AllocsPerRun(200, func() { _, _, _ = server.Relay(ctx, c1, c2) })
	t.Logf("Relay on another ctx: %.0f allocs", n)
}

func BenchmarkHandshake(b *testing.B) {
	s := &server.Server{Handler: replyHandler()}
	c := &memConn{script: cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"))}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		c.off = 0
		_ = s.ServeConn(ctx, c)
	}
}

// One pipelined CONNECT + echo over loopback, harness included, as the bench's allocs/op counts it.
func BenchmarkConnect(b *testing.B) {
	r, err := startRig(newServer("", ""), "127.0.0.1")
	if err != nil {
		b.Fatal(err)
	}
	defer r.close()
	k := kase{host: "127.0.0.1", split: oneWrite}
	b.ReportAllocs()
	for b.Loop() {
		if err := r.run(context.Background(), k); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayThroughput(b *testing.B) {
	echo := echoTCP(b, "127.0.0.1:0")
	c := tunnel(b, serve(b, open()), echo)
	_ = c.SetDeadline(time.Time{})
	chunk := payload()[:256<<10]
	buf := make([]byte, len(chunk))
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	go func() {
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()
	for b.Loop() {
		if _, err := io.ReadFull(c, buf); err != nil {
			b.Fatal(err)
		}
	}
	c.Close()
}

// Zero allocations per datagram once the target is known.
func TestUDPZeroAllocs(t *testing.T) {
	e := udpSock(t)
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := e.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			_, _ = e.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	proxy := serve(t, assocServer(&server.AssociateHandler{Filter: server.AllowAll}, nil))
	_, relay := assoc(t, proxy, "0.0.0.0:0")
	c := udpSock(t)
	msg := dgram(apOf(e.LocalAddr()), "ping")
	ra := relay.AddrPort()
	buf := make([]byte, 2048)
	rt := func() {
		_, _ = c.WriteToUDPAddrPort(msg, ra)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := c.ReadFromUDPAddrPort(buf); err != nil {
			t.Fatal(err)
		}
	}
	rt()
	if n := testing.AllocsPerRun(200, rt); n > 0.5 {
		t.Errorf("%.2f allocs per datagram round trip", n)
	}
}

// refServe is a minimal no-auth CONNECT server: the allocation yardstick.
func refServe(ln net.Listener, dialTimeout time.Duration) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			br := bufio.NewReader(c)
			h := make([]byte, 2)
			if _, err := io.ReadFull(br, h); err != nil {
				return
			}
			if _, err := io.ReadFull(br, make([]byte, h[1])); err != nil {
				return
			}
			_, _ = c.Write([]byte{5, 0})
			_, addr, err := wire.ReadRequest(br)
			if err != nil {
				return
			}
			t, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", addr.String())
			if err != nil {
				return
			}
			defer t.Close()
			_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			go func() { _, _ = io.Copy(t, br); _ = t.(*net.TCPConn).CloseWrite() }()
			_, _ = io.Copy(c, t)
		}()
	}
}

// The reference sets no ctx or TCP_USER_TIMEOUT, which cost this server a few allocations on Linux.
func BenchmarkConnectVsReference(b *testing.B) {
	for _, timeout := range []time.Duration{30 * time.Second, -1} {
		for _, name := range []string{"server", "reference"} {
			b.Run(fmt.Sprintf("%s/timeout=%v", name, timeout), func(b *testing.B) {
				s := open()
				s.Handler = &server.ConnectHandler{Filter: server.AllowAll, DialTimeout: timeout}
				defer s.Close()
				serve := func(ln net.Listener) { _ = s.Serve(ln) }
				if name == "reference" {
					serve = func(ln net.Listener) { refServe(ln, max(timeout, 0)) }
				}
				r := &rig{srv: s}
				lns, port, err := echoListeners("127.0.0.1")
				if err != nil {
					b.Fatal(err)
				}
				for _, ln := range lns {
					r.wg.Go(func() { r.echo(ln) })
				}
				pln := listenLoopback(b)
				r.wg.Go(func() { serve(pln) })
				r.proxy, r.target, r.listeners = pln.Addr().String(), net.JoinHostPort("127.0.0.1", port), append(lns, pln)
				defer r.close()
				k := kase{host: "127.0.0.1", split: oneWrite}
				b.ReportAllocs()
				for b.Loop() {
					if err := r.run(context.Background(), k); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
