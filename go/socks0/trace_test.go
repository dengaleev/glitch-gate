package socks0_test

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var fullTrace = []string{
	"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod username/password",
	"AuthDone ok", "GotReply succeeded 192.0.2.1:1080", "HandshakeDone ok",
}

// Config.Trace runs first, then the ctx's, newest first.
func TestTraceOrder(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var ev events
			cfg := &socks0.Config{Mode: mode, Auth: socks0.UserPass{}, Trace: ev.trace("cfg")}
			ctx := socks0.WithClientTrace(t.Context(), ev.trace("ctx1"))
			ctx = socks0.WithClientTrace(ctx, ev.trace("ctx2"))
			d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve), Config: cfg}
			c, err := d.DialContext(ctx, "tcp", "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write([]byte("x"))
			readN(t, c, 1)
			log := ev.get()
			for _, tag := range []string{"cfg", "ctx1", "ctx2"} {
				if got := only(log, tag); !slices.Equal(got, fullTrace) {
					t.Errorf("%s hooks: %q", tag, got)
				}
			}
			if l := log[:3]; !slices.Equal(l, []string{"cfg:ConnectStart", "ctx2:ConnectStart", "ctx1:ConnectStart"}) {
				t.Errorf("order %q", l)
			}
		})
	}
}

// The hooks run in order for a server sending a byte at a time; HandshakeDone runs iff WroteHandshake ran.
func TestTraceHooks(t *testing.T) {
	start := []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok"}
	for _, tt := range []struct {
		name string
		srv  []byte
		eof  bool
		want []string // after start
	}{
		{"ok", serverMsgs(true, "192.0.2.1:1"), false, []string{"GotMethod username/password", "AuthDone ok", "GotReply succeeded 192.0.2.1:1", "HandshakeDone ok"}},
		{"method", []byte{5, 0xFF}, true, []string{"GotMethod no acceptable methods", "HandshakeDone err"}},
		{"EOF at method", nil, true, []string{"HandshakeDone err"}},
		{"auth EOF", []byte{5, 2}, true, []string{"GotMethod username/password", "AuthDone err", "HandshakeDone err"}},
		{"auth rejected", []byte{5, 2, 1, 1}, true, []string{"GotMethod username/password", "AuthDone err", "HandshakeDone err"}},
		{"reply refused", append([]byte{5, 2, 1, 0}, reply(5, "0.0.0.0:0")...), true,
			[]string{"GotMethod username/password", "AuthDone ok", "GotReply connection refused 0.0.0.0:0", "HandshakeDone err"}},
		{"reply truncated", []byte{5, 2, 1, 0, 5, 0, 0, 1}, true, []string{"GotMethod username/password", "AuthDone ok", "HandshakeDone err"}},
	} {
		for _, mode := range modes {
			for _, viaDialer := range []bool{true, false} {
				var ev events
				mc := newMem(tt.srv)
				mc.chunk = 1
				if tt.eof {
					mc.closeServer()
				}
				if c, _ := hsRun(t, mc, mode, upAuth, viaDialer, ev.trace("t")); c != nil {
					c.Close()
				}
				want := append(slices.Clone(start), tt.want...)
				if !viaDialer {
					want = want[2:]
				}
				if got := only(ev.get(), "t"); !slices.Equal(got, want) {
					t.Errorf("%s/%v/dialer=%v:\n got %q\nwant %q", tt.name, mode, viaDialer, got, want)
				}
			}
		}
	}
	// Before the handshake: a config error runs none, a proxy dial error the connect hooks.
	for _, mode := range modes {
		for _, tt := range []struct {
			name string
			d    *socks0.Dialer
			want []string
		}{
			{"config", &socks0.Dialer{ProxyDial: noDial(t), Config: &socks0.Config{Mode: mode, Auth: interactive{0x80}}}, nil}, // valid in L0
			{"proxy dial", &socks0.Dialer{ProxyDial: func(context.Context, string, string) (net.Conn, error) { return nil, errTest }, Config: &socks0.Config{Mode: mode}},
				[]string{"ConnectStart", "ConnectDone err"}},
		} {
			if tt.name == "config" && mode == socks0.ModeSequential {
				continue
			}
			var ev events
			tt.d.Config.Trace = ev.trace("t")
			handshakeErr(t.Context(), tt.d, "example.com:80")
			if got := only(ev.get(), "t"); !slices.Equal(got, tt.want) {
				t.Errorf("%s/%v: hooks %q, want %q", tt.name, mode, got, tt.want)
			}
		}
	}
}

// A Client runs Config.Trace; a HandshakeContext starting the handshake adds its ctx's hooks.
func TestTraceClient(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var ev events
			cfg := &socks0.Config{Mode: mode, Auth: socks0.UserPass{}, Trace: ev.trace("cfg")}
			c, _ := client(t, proxy{}.serve, cfg)
			c.Write([]byte("x"))
			readN(t, c, 1)
			if got := only(ev.get(), "cfg"); !slices.Equal(got, fullTrace[2:]) {
				t.Errorf("implicit: %q", got)
			}
			ev = events{}
			c, _ = client(t, proxy{}.serve, cfg)
			if err := c.HandshakeContext(socks0.WithClientTrace(t.Context(), ev.trace("ctx"))); err != nil {
				t.Fatal(err)
			}
			log := ev.get()
			if !slices.Equal(only(log, "cfg"), fullTrace[2:]) || !slices.Equal(only(log, "ctx"), fullTrace[2:]) {
				t.Errorf("HandshakeContext: %q", log)
			}
		})
	}
	var ev events
	c := socks0.Client(newMem(goodReplies), "x:1", early())
	c.Write([]byte("x"))
	if err := c.HandshakeContext(socks0.WithClientTrace(t.Context(), ev.trace("t"))); err != nil {
		t.Fatal(err)
	}
	if got := ev.get(); len(got) != 0 {
		t.Errorf("a HandshakeContext not starting the handshake ran its ctx's hooks: %q", got)
	}
}

// In ModeEarly, HandshakeDone runs last and after WroteHandshake even if the handshake ends while
// its first write is returning: by Close (no reader busy), by cancelling a reader of the replies,
// or by the replies a concurrent reader got.
func TestTraceEarlyDoneAfterWrote(t *testing.T) {
	cancelled := func(t *testing.T, c *socks0.Conn, reading chan struct{}) {
		ctx, cancel := context.WithCancel(t.Context())
		errc := make(chan error, 1)
		go func() { errc <- c.HandshakeContext(ctx) }()
		<-reading
		cancel()
		if err := <-errc; err == nil {
			t.Error("HandshakeContext = nil")
		}
	}
	for _, tc := range []struct {
		name   string
		server []byte
		end    func(*testing.T, *socks0.Conn, chan struct{}) // ends the handshake while the write holds
		done   string
	}{
		{"close", nil, func(t *testing.T, c *socks0.Conn, _ chan struct{}) {
			c.Close()
			if c.SetReadDeadline(time.Now()) != nil || c.SetWriteDeadline(time.Now()) != nil {
				t.Error("SetDeadline while the closed handshake ends")
			}
		}, "HandshakeDone err"},
		{"cancel", nil, cancelled, "HandshakeDone err"},
		{"replies", goodReplies, func(t *testing.T, c *socks0.Conn, _ chan struct{}) {
			if err := c.HandshakeContext(t.Context()); err != nil {
				t.Error(err)
			}
		}, "HandshakeDone ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The first Write puts its bytes on the wire, then holds until release.
			mc := newMem(tc.server)
			wrote, release, reading := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var wonce, ronce sync.Once
			mc.onWrite = func(b []byte) (int, error) { wonce.Do(func() { close(wrote); <-release }); return len(b), nil }
			mc.onRead = func() { ronce.Do(func() { close(reading) }) }
			var ev events
			c := socks0.Client(mc, "example.com:80", early(func(cfg *socks0.Config) { cfg.Trace = ev.trace("t") }))
			defer c.Close()
			var wg sync.WaitGroup
			wg.Go(func() { c.Write([]byte("x")) })
			<-wrote
			tc.end(t, c, reading)
			close(release)
			wg.Wait()
			got := only(ev.get(), "t")
			wroteAt := slices.Index(got, "WroteHandshake ok")
			done := slices.IndexFunc(got, func(s string) bool { return s == "HandshakeDone ok" || s == "HandshakeDone err" })
			if wroteAt < 0 || done != len(got)-1 || got[done] != tc.done || wroteAt > done {
				t.Errorf("hooks %q; want WroteHandshake ok, then %s last", got, tc.done)
			}
			if tc.name == "close" && len(got) != 2 {
				t.Errorf("hooks %q; want no reply hooks", got)
			}
		})
	}
}

// Hooks may call the Conn's non-handshake methods, or Close, without deadlocking.
func TestTraceHooksReenter(t *testing.T) {
	for _, mode := range modes {
		var c *socks0.Conn
		poke := func() {
			c.BoundAddr()
			c.SetDeadline(time.Now().Add(time.Second))
			c.LocalAddr()
		}
		tr := &socks0.ClientTrace{
			WroteHandshake: func(error) { poke() },
			GotMethod:      func(wire.Method) { poke() },
			AuthDone:       func(error) { poke() },
			GotReply:       func(wire.Reply, wire.Addr) { poke() },
			HandshakeDone:  func(error) { poke() },
		}
		c = socks0.Client(newMem(serverMsgs(true, "192.0.2.1:1")), "x:1", &socks0.Config{Mode: mode, Auth: upAuth, Trace: tr})
		done := make(chan error, 1)
		go func() { done <- c.HandshakeContext(context.Background()) }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%v: %v", mode, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%v: deadlock with re-entrant hooks", mode)
		}
		var c2 *socks0.Conn
		c2 = socks0.Client(newMem(serverMsgs(false, "192.0.2.1:1")), "x:1", &socks0.Config{Mode: mode, Trace: &socks0.ClientTrace{GotMethod: func(wire.Method) { c2.Close() }}})
		go func() { done <- c2.HandshakeContext(context.Background()) }()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Logf("%v: Close in GotMethod: %v", mode, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%v: deadlock with Close in a hook", mode)
		}
	}
}

func TestWithClientTrace(t *testing.T) {
	ctx := t.Context()
	if socks0.WithClientTrace(ctx, nil) != ctx || socks0.ContextClientTrace(ctx) != nil {
		t.Error("nil trace")
	}
	var ev events
	a := &socks0.ClientTrace{GotReply: func(wire.Reply, wire.Addr) { ev.add("a") }, ConnectDone: func(string, string, error) { ev.add("a connected") }}
	b := &socks0.ClientTrace{GotReply: func(wire.Reply, wire.Addr) { ev.add("b") }, HandshakeDone: func(error) { ev.add("b done") },
		Accepted: func(wire.Addr, error) { ev.add("b accepted") }, RelayDialDone: func(string, string, error) { ev.add("b relay") }}
	ctx = socks0.WithClientTrace(ctx, a)
	if socks0.ContextClientTrace(ctx) != a {
		t.Error("ContextClientTrace")
	}
	ctx = socks0.WithClientTrace(ctx, b)
	tr := socks0.ContextClientTrace(ctx)
	tr.GotReply(0, wire.Addr{})
	tr.HandshakeDone(nil)
	tr.ConnectDone("tcp", "", nil)
	tr.Accepted(wire.Addr{}, nil)
	tr.RelayDialDone("udp", "", nil)
	if tr.ConnectStart != nil {
		t.Error("ConnectStart composed from nils")
	}
	if got := ev.get(); !slices.Equal(got, []string{"b", "a", "b done", "a connected", "b accepted", "b relay"}) {
		t.Errorf("composed hooks ran %q", got)
	}
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
	if tm.ProxyConnect <= 0 || tm.Handshake < 20*time.Millisecond || tm.RelayDial != 0 || tm.Total < tm.ProxyConnect+tm.Handshake {
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
	// UDP: the relay dial too, after the reply and before HandshakeDone.
	var ev events
	d = &socks0.Dialer{ProxyAddr: listenProxy(t), Config: &socks0.Config{Trace: tr}}
	u, err := d.DialContext(socks0.WithClientTrace(t.Context(), ev.trace("u")), "udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	u.Close()
	if tm.RelayDial <= 0 || tm.Total < tm.ProxyConnect+tm.Handshake+tm.RelayDial {
		t.Errorf("UDP: %+v", tm)
	}
	if got := only(ev.get(), "u"); len(got) != 8 || !strings.HasPrefix(got[4], "GotReply ") || !slices.Equal(got[5:], []string{"RelayDialStart udp4", "RelayDialDone ok", "HandshakeDone ok"}) {
		t.Errorf("UDP hooks %q", got)
	}
	// A Client conn has no proxy dial: nothing is timed, nothing panics.
	var tc socks0.Timings
	cc := socks0.Client(newMem(goodReplies), "192.0.2.2:80", &socks0.Config{Trace: tc.Trace()})
	if err := cc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if tc.Handshake != 0 || tc.Total != 0 {
		t.Errorf("Client: %+v", tc)
	}
}
