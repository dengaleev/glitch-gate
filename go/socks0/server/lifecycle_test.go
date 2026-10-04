package server_test

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func listenLoopback(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func tunnel(t testing.TB, proxy, target string) *net.TCPConn {
	t.Helper()
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
	expect(t, c, []byte{5, 0})
	readReply(t, c, wire.CmdConnect)
	return c
}

func TestShutdown(t *testing.T) {
	noLeaks(t)
	target := echoTCP(t, "127.0.0.1:0")
	s := open()
	var hooked atomic.Int32
	s.RegisterOnShutdown(func() { hooked.Add(1) })
	ln := listenLoopback(t)
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	proxy := ln.Addr().String()

	tun := tunnel(t, proxy, target)
	hs := dial(t, proxy) // in the handshake
	_, _ = hs.Write([]byte{5})
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with a live tunnel: %v", err)
	}
	if err := <-served; !errors.Is(err, server.ErrServerClosed) {
		t.Fatalf("Serve: %v", err)
	}
	expectEOF(t, hs) // closed without a reply
	_, _ = tun.Write([]byte("still up"))
	expect(t, tun, []byte("still up")) // tunnels are not cut
	waitFor(t, func() bool { return hooked.Load() == 1 })

	if err := s.Serve(listenLoopback(t)); !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("Serve after Shutdown: %v", err)
	}
	if err := s.ListenAndServe(); !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("ListenAndServe after Shutdown: %v", err)
	}
	a, b := net.Pipe()
	if err := s.ServeConn(context.Background(), b); !errors.Is(err, server.ErrServerClosed) {
		t.Errorf("ServeConn after Shutdown: %v", err)
	}
	if _, err := a.Write([]byte{5}); err == nil {
		t.Error("ServeConn left the conn open")
	}

	_ = tun.CloseWrite()
	expectEOF(t, tun)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	if hooked.Load() != 1 {
		t.Error("hooks ran twice")
	}
}

func TestClose(t *testing.T) {
	noLeaks(t)
	target := echoTCP(t, "127.0.0.1:0")
	e := echoUDP(t, "127.0.0.1:0")
	s := open()
	s.Handler = &server.Mux{
		Connect:   &server.ConnectHandler{Filter: server.AllowAll},
		Associate: &server.AssociateHandler{Filter: server.AllowAll},
		Bind:      &server.BindHandler{Filter: server.AllowAll},
	}
	ln := listenLoopback(t)
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	proxy := ln.Addr().String()

	tun := tunnel(t, proxy, target)
	udp, relay := assoc(t, proxy, "0.0.0.0:0")
	pc := udpSock(t)
	_, _ = pc.WriteTo(dgram(apOf(e.LocalAddr()), "x"), relay)
	recv(pc, 5*time.Second)
	bind := dial(t, proxy)
	_, _ = bind.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0")))
	expect(t, bind, []byte{5, 0})
	readReply(t, bind, wire.CmdBind)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*net.TCPConn{tun, udp, bind} {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, err := c.Read(make([]byte, 100)); err != nil {
				if timedOut(err) {
					t.Fatal("conn not cut by Close")
				}
				break
			}
		}
	}
	if err := <-served; !errors.Is(err, server.ErrServerClosed) {
		t.Fatal(err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestServeConnContext(t *testing.T) {
	noLeaks(t)
	type key struct{}
	s := open()
	s.ConnContext = func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, key{}, "conn") }
	got := make(chan any, 2)
	s.Handler = server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
		got <- ctx.Value(key{})
		<-ctx.Done()
		return ctx.Err()
	})
	s.Trace = &server.ServerTrace{Done: func(ctx context.Context, _ *server.Request, _ server.ConnStats, _ error) { got <- ctx.Value(key{}) }}
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- s.ServeConn(ctx, b) }()
	go func() { _, _ = a.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"))) }()
	expect(t, a, []byte{5, 0})
	if v := <-got; v != "conn" {
		t.Errorf("handler ctx value %v", v)
	}
	cancel() // closes the conn and cancels the handler
	if err := result(t, errc); !errors.Is(err, context.Canceled) {
		t.Errorf("ServeConn: %v", err)
	}
	if v := <-got; v != "conn" {
		t.Errorf("trace ctx value %v", v)
	}
	a.Close()
}

func TestBaseContext(t *testing.T) {
	type key struct{}
	s := open()
	got := make(chan any, 1)
	s.BaseContext = func(net.Listener) context.Context { return context.WithValue(context.Background(), key{}, "base") }
	s.Handler = server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
		got <- ctx.Value(key{})
		return errors.New("stop")
	})
	c := dial(t, serve(t, s))
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
	if v := <-got; v != "base" {
		t.Fatal(v)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, s := range map[string]*server.Server{
		"duplicate":     {Auth: []server.Authenticator{server.NoAuth{}, server.NoAuth{}}},
		"nil":           {Auth: []server.Authenticator{nil}},
		"no acceptable": {Auth: []server.Authenticator{badMethod{}}},
		"versions":      {Versions: 8},
	} {
		t.Run(name, func(t *testing.T) {
			err := s.Serve(listenLoopback(t))
			if socks0.KindOf(err) != socks0.KindConfig {
				t.Fatalf("Serve: %v", err)
			}
			a, b := net.Pipe()
			if err := s.ServeConn(context.Background(), b); socks0.KindOf(err) != socks0.KindConfig {
				t.Fatalf("ServeConn: %v", err)
			}
			if _, err := a.Write([]byte{5}); err == nil {
				t.Error("conn left open")
			}
		})
	}
}

type badMethod struct{ server.NoAuth }

func (badMethod) Method() wire.Method { return wire.MethodNoAcceptable }

type flakyListener struct {
	net.Listener
	fails atomic.Int32
}

type tempErr struct{}

func (tempErr) Error() string   { return "too many open files" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fails.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Err: tempErr{}}
	}
	return l.Listener.Accept()
}

func TestAcceptBackoff(t *testing.T) {
	logs := &logBuf{}
	s := open()
	s.ErrorLog = newLogger(logs)
	fl := &flakyListener{Listener: listenLoopback(t)}
	fl.fails.Store(3)
	go func() { _ = s.Serve(fl) }()
	defer s.Close()
	target := echoTCP(t, "127.0.0.1:0")
	c := tunnel(t, fl.Addr().String(), target)
	c.Close()
	if n := strings.Count(logs.String(), "accept error"); n != 3 {
		t.Errorf("%d accept errors logged:\n%s", n, logs)
	}
	// A non-net error ends Serve.
	s2 := open()
	if err := s2.Serve(errListener{fl}); err == nil || errors.Is(err, server.ErrServerClosed) {
		t.Errorf("Serve: %v", err)
	}
}

type errListener struct{ net.Listener }

var errBroken = errors.New("broken listener")

func (errListener) Accept() (net.Conn, error) { return nil, errBroken }

func TestListenAndServe(t *testing.T) {
	ln := listenLoopback(t)
	addr := ln.Addr().String()
	ln.Close()
	s := open()
	s.Addr = addr
	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe() }()
	waitFor(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, server.ErrServerClosed) {
		t.Fatal(err)
	}
}

func TestNoFDLeak(t *testing.T) {
	dir := "/proc/self/fd"
	if runtime.GOOS == "darwin" {
		dir = "/dev/fd"
	}
	count := func() int {
		es, err := os.ReadDir(dir)
		if err != nil {
			t.Skip(err)
		}
		return len(es)
	}
	target := echoTCP(t, "127.0.0.1:0")
	e := echoUDP(t, "127.0.0.1:0")
	before := count()
	func() {
		s := open()
		s.Handler = &server.Mux{Connect: &server.ConnectHandler{Filter: server.AllowAll}, Associate: &server.AssociateHandler{Filter: server.AllowAll}}
		ln := listenLoopback(t)
		go func() { _ = s.Serve(ln) }()
		for range 20 {
			c := tunnel(t, ln.Addr().String(), target)
			_, _ = c.Write([]byte("x"))
			expect(t, c, []byte("x"))
			c.Close()
			u, relay := assoc(t, ln.Addr().String(), "0.0.0.0:0")
			pc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			_, _ = pc.WriteTo(dgram(apOf(e.LocalAddr()), "x"), relay)
			recv(pc, 5*time.Second)
			pc.Close()
			u.Close()
			bad := dial(t, ln.Addr().String())
			_, _ = bad.Write([]byte{9})
			bad.Close()
		}
		s.Close()
		if err := s.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()
	waitFor(t, func() bool { return count() <= before })
}
