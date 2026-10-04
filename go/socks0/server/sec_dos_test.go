package server_test

// Security review regressions: resource use, UDP, buffer lifetimes.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Reports what an idle pre-auth conn costs the zero Server.
func TestSecInfo_IdleHandshakeCost(t *testing.T) {
	const n = 1000
	var inNew atomic.Int64
	s := &server.Server{ErrorLog: quietLog, ConnState: func(_ net.Conn, st server.ConnState) {
		if st == server.StateNew {
			inNew.Add(1)
		}
	}}
	proxy := serve(t, s)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	g0 := runtime.NumGoroutine()
	conns := make([]net.Conn, 0, n)
	for range n {
		c, err := net.Dial("tcp", proxy)
		if err != nil {
			t.Fatalf("after %d: %v", len(conns), err)
		}
		conns = append(conns, c)
	}
	for end := time.Now().Add(5 * time.Second); inNew.Load() < n && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	g1 := runtime.NumGoroutine()
	for _, c := range conns {
		c.Close()
	}
	d := int64(m1.HeapInuse+m1.StackInuse) - int64(m0.HeapInuse+m0.StackInuse)
	t.Logf("%d idle conns: +%d goroutines, heap+stacks +%d KiB (~%d B/conn incl. client side)", inNew.Load(), g1-g0, d>>10, d/n)
}

// L8: the zero Server caps the handshake phase at 1024 conns.
func TestSec_DefaultMaxHandshakes(t *testing.T) {
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
}

// L7: datagrams that get dropped do not keep an association alive.
func TestSec_UDPIdleNotRefreshedByDroppedDatagrams(t *testing.T) {
	var drops atomic.Int32
	s := &server.Server{
		ErrorLog: quietLog,
		Handler:  &server.AssociateHandler{IdleTimeout: 300 * time.Millisecond, Filter: server.AllowAll},
		Trace:    &server.ServerTrace{Dropped: func(context.Context, netip.AddrPort, error) { drops.Add(1) }},
	}
	proxy := serve(t, s)
	c := dial(t, proxy)
	// Port 1 makes every real datagram "wrong source".
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "127.0.0.1:1")))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdUDPAssociate)
	spray, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP(), bound.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer spray.Close()
	for stop := time.Now().Add(1500 * time.Millisecond); time.Now().Before(stop); time.Sleep(100 * time.Millisecond) {
		_, _ = spray.Write([]byte("junk"))
	}
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	if drops.Load() == 0 || timedOut(err) {
		t.Fatalf("IdleTimeout 300ms, after 1.5s of dropped datagrams (%d drops): association alive (%v)", drops.Load(), err)
	}
}

// L4: DST 0.0.0.0:P locks the client port at once, so a forged first datagram cannot win.
func TestSec_UDPDSTPortLocksUnspecifiedAddr(t *testing.T) {
	e := echoUDP(t, "127.0.0.1:0")
	var mu sync.Mutex
	var drops []string
	s := &server.Server{ErrorLog: quietLog, Handler: &server.AssociateHandler{Filter: server.AllowAll},
		Trace: &server.ServerTrace{Dropped: func(_ context.Context, from netip.AddrPort, err error) {
			mu.Lock()
			defer mu.Unlock()
			drops = append(drops, fmt.Sprint(from, " ", err))
		}}}
	proxy := serve(t, s)
	victim, attacker := udpSock(t), udpSock(t)
	vport := victim.LocalAddr().(*net.UDPAddr).Port
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, fmt.Sprintf("0.0.0.0:%d", vport))))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdUDPAssociate)
	relay := netip.AddrPortFrom(bound.IP(), bound.Port())
	msg := dgram(apOf(e.LocalAddr()), "first")
	_, _ = attacker.WriteToUDPAddrPort(msg, relay) // forged first datagram
	time.Sleep(50 * time.Millisecond)
	_, _ = victim.WriteToUDPAddrPort(msg, relay)
	_ = victim.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := victim.ReadFromUDPAddrPort(buf)
	mu.Lock()
	defer mu.Unlock()
	if err != nil || !bytes.HasSuffix(buf[:n], []byte("first")) || len(drops) != 1 || !strings.Contains(drops[0], "another source") {
		t.Fatalf("victim: %q, %v; drops %q", buf[:n], err, drops)
	}
}

// Reports the relay's bytes-out per byte-in for small datagrams.
func TestSecInfo_UDPAmplification(t *testing.T) {
	echo := echoUDP(t, "127.0.0.1:0")
	s := &server.Server{ErrorLog: quietLog, Handler: &server.AssociateHandler{Filter: server.AllowAll}}
	proxy := serve(t, s)
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdUDPAssociate)
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP(), bound.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(echo.LocalAddr().(*net.UDPAddr).AddrPort()))
	var in, out int
	b := make([]byte, 2048)
	for i := range 200 {
		d := append(bytes.Clone(h), bytes.Repeat([]byte{'x'}, 1+i%64)...)
		_, _ = u.Write(d)
		in += len(d)
		_ = u.SetReadDeadline(time.Now().Add(time.Second))
		n, err := u.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		out += n
	}
	t.Logf("client->relay %d B, relay->client %d B: ratio %.2f; target gets payload only (no amplification to third parties)", in, out, float64(out)/float64(in))
}

// L5: a slice of the conn buffer kept too long (Early here) never shows another conn's bytes.
func TestSec_StaleSlicesIsolated(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	secret := []byte("Cookie: session=VICTIM-SECRET-0123456789abcdef")
	mine := bytes.Repeat([]byte{'A'}, len(secret))
	var (
		mu     sync.Mutex
		stale  []byte
		leaked int
	)
	drained := make(chan struct{}, 1)
	next := make(chan struct{}, 1)
	victimIn := make(chan struct{}, 1)
	checked := make(chan struct{}, 1)
	s := open()
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		e := r.Early()
		if !bytes.Equal(e, mine) { // victim
			victimIn <- struct{}{}
			<-checked
		}
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			return err
		}
		if bytes.Equal(e, mine) { // careless handler
			mu.Lock()
			stale = e // misuse: kept past Reply
			mu.Unlock()
			_, _ = io.ReadFull(c, make([]byte, len(mine))) // releases the buffer
			drained <- struct{}{}
			<-next
			return nil
		}
		_, _ = io.Copy(io.Discard, c)
		return nil
	})
	proxy := serve(t, s)
	const tries = 20
	for range tries {
		a := dial(t, proxy)
		_, _ = a.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), mine))
		<-drained
		v := dial(t, proxy)
		_, _ = v.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), secret))
		<-victimIn
		mu.Lock()
		if bytes.Contains(stale, []byte("VICTIM")) {
			leaked++
		}
		mu.Unlock()
		checked <- struct{}{}
		_ = v.CloseWrite()
		_, _ = io.ReadAll(v)
		next <- struct{}{}
		_ = a.CloseWrite()
		_, _ = io.ReadAll(a)
	}
	if leaked > 0 {
		t.Fatalf("a stale Early() slice read another conn's early data in %d of %d tries", leaked, tries)
	}
}

// Concurrent tunnels (splice on Linux) never see each other's bytes.
func TestSecOK_RelayHammerNoCrossTalk(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	proxy := serve(t, open())
	const conns, par = 400, 64
	var wg sync.WaitGroup
	sem := make(chan struct{}, par)
	for id := range conns {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			mark := fmt.Appendf(nil, "<conn %04d>", id)
			early := bytes.Repeat(mark, 1+id%250)
			rest := bytes.Repeat(mark, 1+(id*37)%9000)
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))
			go func() {
				_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target), early))
				_, _ = c.Write(rest)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if err != nil || len(got) < 2+10 || !bytes.Equal(got[:2], []byte{5, 0}) || !bytes.Equal(got[12:], cat(early, rest)) {
				t.Errorf("conn %d: %d bytes, %v", id, len(got), err)
			}
		})
	}
	wg.Wait()
}

// L9: MaxConns holds across listeners, and a freed slot wakes every waiting listener.
func TestSec_MaxConnsMultiListener(t *testing.T) {
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
		var lns []net.Listener
		for range 2 {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			lns = append(lns, ln)
			go func() { _ = s.Serve(ln) }()
		}
		h1 := dial(t, lns[0].Addr().String())
		h2 := dial(t, lns[1].Addr().String())
		time.Sleep(50 * time.Millisecond)
		h1.Close()
		time.Sleep(50 * time.Millisecond)
		h2.Close()
		time.Sleep(50 * time.Millisecond)
		served := false
		if c, err := net.Dial("tcp", lns[try%2].Addr().String()); err == nil {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
			b, _ := io.ReadAll(c)
			served = len(b) >= 2
			c.Close()
		}
		_ = s.Close()
		if !served || peak.Load() > 1 {
			t.Fatalf("try %d: probe on listener %d served %v; peak %d conns with MaxConns 1", try, try%2, served, peak.Load())
		}
	}
}

func panicFilter(*server.Request, string, netip.AddrPort) error { panic("filter bug") }

// L10: a relay-goroutine panic is logged and ends the association.
func TestSec_UDPRelayPanicRecovered(t *testing.T) {
	var lb logBuf
	done := make(chan error, 1)
	s := &server.Server{ErrorLog: newLogger(&lb), Handler: &server.AssociateHandler{Filter: panicFilter},
		Trace: &server.ServerTrace{Done: func(_ context.Context, _ *server.Request, _ server.ConnStats, err error) { done <- err }}}
	c := dial(t, serve(t, s))
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdUDPAssociate)
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP(), bound.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_, _ = u.Write(dgram(netip.MustParseAddrPort("192.0.2.1:53"), "x"))
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "panicked") || !strings.Contains(lb.String(), "filter bug") {
			t.Fatalf("ServeConn: %v; log %q", err, lb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("association alive after a relay panic")
	}
}

// L10: a bad MaxDatagram is a config error and a relay panic is recovered (in a subprocess).
func TestSec_UDPMisconfigNoCrash(t *testing.T) {
	if os.Getenv("SEC_CRASH_CHILD") == "1" {
		secCrashChild()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSec_UDPMisconfigNoCrash$")
	cmd.Env = append(os.Environ(), "SEC_CRASH_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "child ok") {
		t.Fatalf("server process: %v\n%s", err, out)
	}
}

// A negative MaxTargets is a config error, as a bad MaxDatagram is, not a relay dropping every
// datagram; a Mux is validated recursively, and behind a HandlerFunc it fails at request time.
func TestSec_UDPNegativeMaxTargets(t *testing.T) {
	bad := &server.AssociateHandler{MaxTargets: -1}
	for _, tc := range []struct {
		h      server.Handler
		script []byte
	}{
		{bad, nil},
		{&server.Mux{Associate: bad}, nil},
		{&server.Mux{Connect: &server.Mux{Associate: bad}}, nil},
		{server.HandlerFunc(bad.ServeSOCKS), cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0"))},
	} {
		s := &server.Server{ErrorLog: quietLog, Handler: tc.h}
		cli, srv := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, cli) }()
		go func() { _, _ = cli.Write(tc.script) }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // bounds a regression
		err := s.ServeConn(ctx, srv)
		cancel()
		cli.Close()
		if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageConfig || !strings.Contains(err.Error(), "MaxTargets -1") {
			t.Errorf("%T: %v", tc.h, err)
		}
	}
}

func secCrashChild() {
	fail := func(format string, a ...any) {
		fmt.Printf(format+"\n", a...)
		os.Exit(1)
	}
	for _, md := range []int{-1, 1, 10, 22} {
		s := &server.Server{ErrorLog: quietLog, Handler: &server.Mux{Associate: &server.AssociateHandler{MaxDatagram: md}}}
		cli, srv := net.Pipe()
		err := s.ServeConn(context.Background(), srv)
		cli.Close()
		if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageConfig {
			fail("MaxDatagram %d via Mux: %v", md, err)
		}
	}
	// Hidden behind a HandlerFunc: fails at request time.
	h := &server.AssociateHandler{MaxDatagram: 10}
	s := &server.Server{ErrorLog: quietLog, Handler: server.HandlerFunc(h.ServeSOCKS)}
	cli, srv := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, cli) }()
	go func() { _, _ = cli.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0"))) }()
	err := s.ServeConn(context.Background(), srv)
	cli.Close()
	if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageConfig {
		fail("MaxDatagram 10 via HandlerFunc: %v", err)
	}
	var lb logBuf
	s = &server.Server{ErrorLog: newLogger(&lb), Handler: &server.AssociateHandler{Filter: panicFilter}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("%v", err)
	}
	go func() { _ = s.Serve(ln) }()
	defer s.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		fail("%v", err)
	}
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")))
	b := make([]byte, 12)
	if _, err := io.ReadFull(c, b); err != nil {
		fail("reply: %v", err)
	}
	_, bound, _, err := wire.ParseReply(b[2:], wire.CmdUDPAssociate)
	if err != nil {
		fail("reply %x: %v", b, err)
	}
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP(), bound.Port())))
	if err != nil {
		fail("%v", err)
	}
	h2, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:53")))
	_, _ = u.Write(append(h2, "x"...))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(b); !errors.Is(err, io.EOF) {
		fail("control conn after the relay panic: %v", err)
	}
	if !strings.Contains(lb.String(), "panic") || !strings.Contains(lb.String(), "filter bug") {
		fail("panic not logged: %q", lb.String())
	}
	fmt.Println("child ok")
}
