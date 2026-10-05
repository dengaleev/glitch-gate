package server_test

// Server lifecycle and resource limits.

import (
	"context"
	"errors"
	"io"
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

// Shutdown closes the listeners and the conns in the handshake, leaves tunnels up and runs its
// hooks once; then nothing serves again.
func TestShutdown(t *testing.T) {
	noLeaks(t)
	target := echoTCP(t, "127.0.0.1:0")
	s := open()
	var hooked atomic.Int32
	s.RegisterOnShutdown(func() { hooked.Add(1) })
	ln := listenLoopback(t)
	proxy := ln.Addr().String()
	ln.Close()
	s.Addr = proxy
	served := make(chan error, 1)
	go func() { served <- s.ListenAndServe() }()
	waitFor(t, func() bool {
		c, err := net.Dial("tcp", proxy)
		if err == nil {
			c.Close()
		}
		return err == nil
	})

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

// Close cuts every conn, tunnels and associations too, and leaves no goroutine or fd behind.
func TestClose(t *testing.T) {
	noLeaks(t)
	dir := "/proc/self/fd"
	if runtime.GOOS == "darwin" {
		dir = "/dev/fd"
	}
	fds := func() int {
		es, err := os.ReadDir(dir)
		if err != nil {
			t.Skip(err)
		}
		return len(es)
	}
	target := echoTCP(t, "127.0.0.1:0")
	e := echoUDP(t, "127.0.0.1:0")
	datagram := func(relay *net.UDPAddr) *net.UDPConn {
		pc := udpSock(t)
		_, _ = pc.WriteTo(dgram(apOf(e.LocalAddr()), "x"), relay)
		recv(pc, 5*time.Second)
		return pc
	}
	before := fds()
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
	for range 20 {
		c := tunnel(t, proxy, target)
		_, _ = c.Write([]byte("x"))
		expect(t, c, []byte("x"))
		c.Close()
		u, relay := assoc(t, proxy, "0.0.0.0:0")
		datagram(relay).Close()
		u.Close()
		bad := dial(t, proxy)
		_, _ = bad.Write([]byte{9})
		bad.Close()
	}

	tun := tunnel(t, proxy, target)
	udp, relay := assoc(t, proxy, "0.0.0.0:0")
	pc := datagram(relay)
	bind, _, _ := ask(t, proxy, request(wire.CmdBind, "0.0.0.0:0"))
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
		c.Close()
	}
	pc.Close()
	if err := <-served; !errors.Is(err, server.ErrServerClosed) {
		t.Fatal(err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return fds() <= before })
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

type badMethod struct{ server.NoAuth }

func (badMethod) Method() wire.Method { return wire.MethodNoAcceptable }

// A bad config fails Serve and ServeConn before any byte, a built-in handler's in a Mux too;
// behind a HandlerFunc an AssociateHandler checks itself at request time.
func TestConfigErrors(t *testing.T) {
	assocs := map[string]*server.AssociateHandler{
		"MaxDatagram -1": {MaxDatagram: -1},
		"MaxDatagram 1":  {MaxDatagram: 1},
		"MaxDatagram 10": {MaxDatagram: 10},
		"MaxDatagram 22": {MaxDatagram: 22},
		"MaxTargets -1":  {MaxTargets: -1},
	}
	cases := map[string]*server.Server{
		"duplicate":     {Auth: []server.Authenticator{server.NoAuth{}, server.NoAuth{}}},
		"nil":           {Auth: []server.Authenticator{nil}},
		"no acceptable": {Auth: []server.Authenticator{badMethod{}}},
		"versions":      {Versions: 8},
	}
	for name, h := range assocs {
		cases[name] = &server.Server{Handler: h}
		cases[name+" in Mux"] = &server.Server{Handler: &server.Mux{Associate: h}}
		cases[name+" in nested Mux"] = &server.Server{Handler: &server.Mux{Connect: &server.Mux{Associate: h}}}
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			s.ErrorLog = quietLog
			if err := s.Serve(listenLoopback(t)); socks0.KindOf(err) != socks0.KindConfig {
				t.Fatalf("Serve: %v", err)
			}
			a, b := net.Pipe()
			err := s.ServeConn(context.Background(), b)
			if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageConfig ||
				socks0.KindOf(err) != socks0.KindConfig || strings.HasPrefix(name, "Max") && !strings.Contains(err.Error(), strings.Split(name, " in")[0]) {
				t.Fatalf("ServeConn: %v", err)
			}
			if _, err := a.Write([]byte{5}); err == nil {
				t.Error("conn left open")
			}
		})
	}
	for name, h := range assocs {
		s := &server.Server{ErrorLog: quietLog, Handler: server.HandlerFunc(h.ServeSOCKS)}
		err := servePipe(t, s, cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")), nil, false)
		if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageConfig || !strings.Contains(err.Error(), name) {
			t.Errorf("%s behind a HandlerFunc: %v", name, err)
		}
	}
}

// Temporary accept errors are logged quoted and retried; others end Serve.
func TestAcceptErrors(t *testing.T) {
	logs := &logBuf{}
	s := open()
	s.ErrorLog = newLogger(logs)
	el := &errListener{Listener: listenLoopback(t)}
	el.errs = []error{&net.OpError{Op: "accept", Err: tempErr("too many open files")}, tempErr(forged), tempErr("again")}
	target := echoTCP(t, "127.0.0.1:0")
	tunnel(t, serveLn(t, s, el), target).Close()
	if n := strings.Count(logs.String(), "accept error"); n != 3 {
		t.Errorf("%d accept errors logged:\n%s", n, logs)
	}
	if !logQuoted(logs.String()) {
		t.Errorf("accept error not quoted: %q", logs)
	}
	errBroken := errors.New("broken listener")
	for _, err := range []error{errBroken, net.ErrClosed} {
		if got := open().Serve(&errListener{Listener: listenLoopback(t), errs: []error{err}}); !errors.Is(got, err) {
			t.Errorf("Serve: %v, want %v", got, err)
		}
	}
}

// MaxHandshakes caps the conns in the handshake, 1024 by default: one over is closed at once, and
// a slot frees when a handshake completes.
func TestMaxHandshakes(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		s := open()
		s.MaxHandshakes = 1
		target := echoTCP(t, "127.0.0.1:0")
		proxy := serve(t, s)
		idle := dial(t, proxy) // holds the only handshake slot
		time.Sleep(50 * time.Millisecond)
		over := dial(t, proxy)
		_ = over.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := over.Read(make([]byte, 1)); n != 0 || err == nil || timedOut(err) {
			t.Fatalf("over the cap: %d, %v; want closed at once", n, err)
		}
		_, _ = idle.Write(cat(greeting(0), request(wire.CmdConnect, target), []byte("x")))
		expect(t, idle, []byte{5, 0})
		readReply(t, idle, wire.CmdConnect)
		expect(t, idle, []byte("x"))
		ask(t, proxy, request(wire.CmdConnect, target))
	})
	t.Run("default", func(t *testing.T) {
		const n = 1100
		var inNew, maxNew atomic.Int64
		s := &server.Server{ErrorLog: quietLog, ConnState: func(_ net.Conn, st server.ConnState) {
			switch st {
			case server.StateNew:
				v := inNew.Add(1)
				for m := maxNew.Load(); v > m && !maxNew.CompareAndSwap(m, v); m = maxNew.Load() {
				}
			case server.StateClosed:
				inNew.Add(-1)
			}
		}}
		proxy := serve(t, s)
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		g0 := runtime.NumGoroutine()
		conns := make([]net.Conn, 0, n)
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for range n {
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Fatalf("after %d: %v", len(conns), err)
			}
			conns = append(conns, c)
		}
		_ = conns[n-1].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conns[n-1].Read(make([]byte, 1)); err == nil || timedOut(err) {
			t.Fatalf("conn over the default cap: %v", err)
		}
		if m := maxNew.Load(); m > 1024 || m < 1000 {
			t.Fatalf("%d conns in the handshake at once, want ≤ 1024", m)
		}
		runtime.GC()
		runtime.ReadMemStats(&m1)
		g1 := runtime.NumGoroutine()
		d := int64(m1.HeapInuse+m1.StackInuse) - int64(m0.HeapInuse+m0.StackInuse)
		t.Logf("%d idle handshakes: +%d goroutines, heap+stacks +%d KiB (~%d B/conn incl. client side)", inNew.Load(), g1-g0, d>>10, d/max(inNew.Load(), 1))
	})
}

// MaxConns holds across listeners, a freed slot wakes every waiting listener, and Close releases
// a conn waiting for one unserved.
func TestMaxConns(t *testing.T) {
	t.Run("backlog", func(t *testing.T) {
		s := open()
		s.MaxConns = 1
		target := echoTCP(t, "127.0.0.1:0")
		proxy := serve(t, s)
		a := tunnel(t, proxy, target)
		b := dial(t, proxy) // in the backlog, not accepted
		_, _ = b.Write(greeting(0))
		_ = b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _ := b.Read(make([]byte, 2)); n != 0 {
			t.Fatal("served over MaxConns")
		}
		a.Close()
		_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
		expect(t, b, []byte{5, 0})
		waiting := dial(t, proxy) // accepted, waiting for b's slot
		time.Sleep(50 * time.Millisecond)
		s.Close()
		expectEOF(t, waiting) // closed unserved
	})
	t.Run("listeners", func(t *testing.T) {
		for try := range 10 {
			var active, peak atomic.Int32
			s := &server.Server{MaxConns: 1, ErrorLog: quietLog, ConnState: func(_ net.Conn, st server.ConnState) {
				switch st {
				case server.StateNew:
					v := active.Add(1)
					for p := peak.Load(); v > p && !peak.CompareAndSwap(p, v); p = peak.Load() {
					}
				case server.StateClosed:
					active.Add(-1)
				}
			}, Handler: server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
				_, err := r.Reply(1, wire.Addr{})
				return err
			})}
			proxies := []string{serve(t, s), serve(t, s)}
			h1, h2 := dial(t, proxies[0]), dial(t, proxies[1])
			time.Sleep(50 * time.Millisecond)
			h1.Close()
			time.Sleep(50 * time.Millisecond)
			h2.Close()
			time.Sleep(50 * time.Millisecond)
			c := dial(t, proxies[try%2])
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
			b, _ := io.ReadAll(c)
			_ = s.Close()
			if len(b) < 2 || peak.Load() > 1 {
				t.Fatalf("try %d: probe on listener %d got %x; peak %d conns with MaxConns 1", try, try%2, b, peak.Load())
			}
		}
	})
}

func TestAdmit(t *testing.T) {
	errBlocked := errors.New("blocked")
	var admitted, released atomic.Int32
	s := open()
	s.Admit = func(ctx context.Context, c net.Conn) (func(), error) {
		n := admitted.Add(1)
		release := func() { released.Add(1) }
		if n%2 == 0 {
			return release, errBlocked
		}
		return release, nil
	}
	target := echoTCP(t, "127.0.0.1:0")
	for i := range 6 {
		c, errc := serveOne(t, s)
		switch i % 3 {
		case 0: // a tunnel
			_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
		case 1: // a failed handshake
			_, _ = c.Write([]byte{9})
		}
		_ = c.CloseWrite()
		_, _ = io.ReadAll(c)
		c.Close()
		err := result(t, errc)
		if blocked := admitted.Load()%2 == 0; blocked != errors.Is(err, errBlocked) {
			t.Errorf("conn %d: %v", i, err)
		}
	}
	if admitted.Load() != 6 || released.Load() != 6 {
		t.Fatalf("admitted %d released %d", admitted.Load(), released.Load())
	}
}
