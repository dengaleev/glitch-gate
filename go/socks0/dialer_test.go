package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestDialModes(t *testing.T) {
	auths := []struct {
		name string
		auth socks0.Authenticator
	}{
		{"noauth", nil},
		{"userpass", socks0.UserPass{Username: "user", Password: "pässword"}},
		{"*userpass", &socks0.UserPass{}},
	}
	for _, mode := range modes {
		for _, a := range auths {
			for _, target := range []string{"198.51.100.7:80", "[2001:db8::7]:443", "example.com:8080"} {
				t.Run(mode.String()+"/"+a.name+"/"+target, func(t *testing.T) {
					got := make(chan request, 1)
					d := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve), Config: &socks0.Config{Mode: mode, Auth: a.auth}}
					c := mustDial(t, d, "tcp", target)
					// L0 and L1 return the proxy conn; L2 a Conn over it.
					switch cc := c.(type) {
					case *net.TCPConn:
						if mode == socks0.ModeEarly {
							t.Fatalf("conn is %T", c)
						}
					case *socks0.Conn:
						if _, ok := cc.NetConn().(*net.TCPConn); mode != socks0.ModeEarly || !ok {
							t.Fatalf("conn is %T over %T", c, cc.NetConn())
						}
						if _, err := cc.SyscallConn(); err != nil {
							t.Error(err)
						}
					default:
						t.Fatalf("conn is %T", c)
					}
					msg := "hello through the proxy"
					c.Write([]byte(msg))
					if s := readN(t, c, len(msg)); s != msg {
						t.Fatalf("echo = %q", s)
					}
					want := request{methods: []wire.Method{wire.MethodNoAuth}, cmd: wire.CmdConnect, target: mustAddr(target)}
					if a.auth != nil {
						want.methods = []wire.Method{wire.MethodUserPass}
						if up, ok := a.auth.(socks0.UserPass); ok {
							want.user, want.pass = up.Username, up.Password
						}
					}
					if req := <-got; !reflect.DeepEqual(req, want) {
						t.Errorf("server got %+v, want %+v", req, want)
					}
					if sc, ok := c.(*socks0.Conn); ok && sc.BoundAddr() != defaultBound {
						t.Errorf("BoundAddr = %v", sc.BoundAddr())
					}
				})
			}
		}
	}
}

func TestDialConfigErrors(t *testing.T) {
	long := strings.Repeat("x", 256)
	for _, tt := range []struct {
		name    string
		network string
		addr    string
		cfg     *socks0.Config
		is      error
	}{
		{"network", "unix", "example.com:80", nil, nil},
		{"udp4 IPv6", "udp4", "[2001:db8::1]:80", nil, nil},
		{"addr", "tcp", "example.com", nil, nil},
		{"port", "tcp", "example.com:http", nil, nil},
		{"tcp4 IPv6", "tcp4", "[2001:db8::1]:80", nil, nil},
		{"tcp6 IPv4", "tcp6", "192.0.2.1:80", nil, nil},
		{"mode", "tcp", "example.com:80", &socks0.Config{Mode: 7}, nil},
		{"nil *UserPass", "tcp", "example.com:80", &socks0.Config{Auth: (*socks0.UserPass)(nil)}, nil},
		{"user too long", "tcp", "example.com:80", &socks0.Config{Auth: socks0.UserPass{Username: long}}, wire.ErrInvalid},
		{"password too long", "tcp", "example.com:80", &socks0.Config{Auth: socks0.UserPass{Password: long}}, wire.ErrInvalid},
		{"method FF", "tcp", "example.com:80", &socks0.Config{Mode: socks0.ModeSequential, Auth: interactive{wire.MethodNoAcceptable}}, nil},
		{"not pipelinable", "tcp", "example.com:80", &socks0.Config{Auth: interactive{0x80}}, socks0.ErrNotPipelinable},
		{"not pipelinable early", "tcp", "example.com:80", &socks0.Config{Mode: socks0.ModeEarly, Auth: interactive{0x80}}, socks0.ErrNotPipelinable},
		{"pipeliner request", "tcp", "example.com:80", &socks0.Config{Auth: pipeliner{reqErr: errTest}}, errTest},
		// OfferNoAuth needs ModeSequential, SOCKS5 and Auth, never silently dropped.
		{"OfferNoAuth pipelined", "tcp", "example.com:80", &socks0.Config{Auth: upAuth, OfferNoAuth: true}, nil},
		{"OfferNoAuth early", "tcp", "example.com:80", &socks0.Config{Mode: socks0.ModeEarly, Auth: upAuth, OfferNoAuth: true}, nil},
		{"OfferNoAuth SOCKS4", "tcp", "192.0.2.2:80", &socks0.Config{Mode: socks0.ModeSequential, Version: 4, OfferNoAuth: true}, nil},
		{"OfferNoAuth SOCKS4 user", "tcp", "192.0.2.2:80", &socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "id"}, OfferNoAuth: true}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var dialed atomic.Bool
			d := &socks0.Dialer{
				ProxyAddr: "192.0.2.1:1080",
				ProxyDial: func(context.Context, string, string) (net.Conn, error) { dialed.Store(true); return nil, errTest },
				Config:    tt.cfg,
			}
			c, err := d.DialContext(t.Context(), tt.network, tt.addr)
			if c != nil || dialed.Load() {
				t.Fatalf("conn %v, dialed %v", c, dialed.Load())
			}
			if he := handshakeErrOf(t, err); he.Stage != socks0.StageConfig || socks0.KindOf(err) != socks0.KindConfig {
				t.Errorf("stage %q, kind %q", he.Stage, socks0.KindOf(err))
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v; want it to match %v", err, tt.is)
			}
			if strings.Contains(err.Error(), long) {
				t.Errorf("err holds the credential: %v", err)
			}
		})
	}
}

func TestDialResolver(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")
	mapped := netip.MustParseAddr("::ffff:192.0.2.8")
	for _, tt := range []struct {
		network string
		ips     []netip.Addr
		lookup  string
		want    string // target sent, or "" for a DNS error
	}{
		{"tcp", []netip.Addr{v6, v4}, "ip", "[2001:db8::9]:80"},
		{"tcp", []netip.Addr{mapped}, "ip", "192.0.2.8:80"},
		{"tcp4", []netip.Addr{v6, v4}, "ip4", "192.0.2.9:80"},
		{"tcp6", []netip.Addr{v4, v6}, "ip6", "[2001:db8::9]:80"},
		{"tcp6", []netip.Addr{v4}, "ip6", ""},
		{"tcp", nil, "ip", ""},
	} {
		got := make(chan request, 1)
		r := &resolver{ips: tt.ips}
		d := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve), Resolver: r}
		c, err := d.DialContext(t.Context(), tt.network, "example.com:80")
		if !slices.Equal(r.got, []string{tt.lookup + " example.com"}) {
			t.Errorf("%s: lookups %q", tt.network, r.got)
		}
		if tt.want == "" {
			if he := handshakeErrOf(t, err); he.Stage != socks0.StageResolve || socks0.KindOf(err) != socks0.KindDNS {
				t.Errorf("%s %v: %v", tt.network, tt.ips, err)
			}
			if op := err.(*net.OpError); op.Addr.String() != "example.com:80" {
				t.Errorf("OpError.Addr = %v", op.Addr)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if req := <-got; req.target.String() != tt.want {
			t.Errorf("%s %v: sent %v, want %v", tt.network, tt.ips, req.target, tt.want)
		}
	}

	// A resolver error; IP literals and the proxy are never looked up.
	r := &resolver{err: errTest}
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve), Resolver: r}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); !errors.Is(err, errTest) {
		t.Errorf("err = %v", err)
	}
	c := mustDial(t, d, "tcp", "192.0.2.1:80")
	c.Close()
	if len(r.got) != 1 {
		t.Errorf("lookups %q", r.got)
	}
}

func TestDialProxyDialError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	d := &socks0.Dialer{ProxyAddr: addr}
	_, err := d.DialContext(t.Context(), "tcp", "example.com:80")
	he := handshakeErrOf(t, err)
	if he.Stage != socks0.StageProxyDial || errnoMapped && (!errors.Is(err, eConnRefused) || socks0.KindOf(err) != socks0.KindRefused) {
		t.Errorf("err = %v (stage %q, kind %q)", err, he.Stage, socks0.KindOf(err))
	}
	if op := err.(*net.OpError); op.Net != "tcp" || op.Source.String() != addr || op.Addr.String() != "example.com:80" {
		t.Errorf("OpError = %+v", op)
	}
	d = &socks0.Dialer{ProxyDial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); handshakeErrOf(t, err).Stage != socks0.StageProxyDial {
		t.Errorf("nil conn: %v", err)
	}
	// A conn returned with an error is closed.
	mc := newMem()
	d = &socks0.Dialer{ProxyAddr: "proxy:1080", ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, errTest }}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); !errors.Is(err, errTest) || mc.closes.Load() == 0 {
		t.Errorf("err %v, conn closed %d times", err, mc.closes.Load())
	}
}

func TestDialCancel(t *testing.T) {
	for _, tt := range []struct {
		name  string
		srv   func(net.Conn)
		auth  socks0.Authenticator
		modes []socks0.Mode
		stage string
	}{
		{"silent", scripted(nil, true), nil, modes[:2], wire.StageMethodSelection},
		{"method only", scripted([]byte{5, 0}, true), nil, modes[:2], wire.StageReply},
		{"auth only", scripted([]byte{5, 2, 1, 0}, true), socks0.UserPass{}, modes[1:2], wire.StageReply},
		{"auth pending", scripted([]byte{5, 2}, true), socks0.UserPass{}, modes[:2], wire.StageUserPassStatus},
		{"auth pending custom", scripted([]byte{5, 0x80}, true), interactive{0x80}, modes[:1], socks0.StageAuth},
	} {
		for _, mode := range tt.modes {
			t.Run(tt.name+"/"+mode.String(), func(t *testing.T) {
				d := &socks0.Dialer{ProxyAddr: listen(t, tt.srv), Config: &socks0.Config{Mode: mode, Auth: tt.auth}}
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				_, err := d.DialContext(ctx, "tcp", "example.com:80")
				he := handshakeErrOf(t, err)
				if he.Stage != tt.stage || !errors.Is(err, context.DeadlineExceeded) || !err.(net.Error).Timeout() || socks0.KindOf(err) != socks0.KindTimeout {
					t.Errorf("deadline: %v (stage %q)", err, he.Stage)
				}
				ctx, cancel = context.WithCancel(t.Context())
				time.AfterFunc(20*time.Millisecond, cancel)
				_, err = d.DialContext(ctx, "tcp", "example.com:80")
				he = handshakeErrOf(t, err)
				if he.Stage != tt.stage || !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled {
					t.Errorf("cancel: %v (stage %q)", err, he.Stage)
				}
			})
		}
	}
	t.Run("canceled before", func(t *testing.T) {
		// It fails and closes the conn, also when ProxyDial ignores the ctx (a pool, a mux).
		for _, mode := range modes {
			for range 300 {
				mc := newMem(goodReplies)
				d := &socks0.Dialer{ProxyAddr: "proxy:1080", Config: &socks0.Config{Mode: mode}, ProxyDial: memDial(mc)}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				c, err := d.DialContext(ctx, "tcp", "example.com:80")
				if err == nil {
					c.Close()
					t.Fatalf("%v: DialContext(canceled) succeeded", mode)
				}
				if !errors.Is(err, context.Canceled) || mc.closes.Load() != 1 {
					t.Fatalf("%v: %v, conn closed %d times", mode, err, mc.closes.Load())
				}
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve)}
		if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
			t.Errorf("canceled ctx: %v", err)
		}
		d.ProxyDial = func(context.Context, string, string) (net.Conn, error) { return nil, errTest }
		if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
			t.Errorf("canceled ctx, failing ProxyDial: %v", err)
		}
	})
	t.Run("cause", func(t *testing.T) {
		// ctx.Err() is wrapped, not context.Cause.
		cause := errors.New("my cause")
		d := &socks0.Dialer{ProxyAddr: "p:1", ProxyDial: memDial(newMem([]byte{5, 0}))}
		ctx, cancel := context.WithCancelCause(context.Background())
		time.AfterFunc(10*time.Millisecond, func() { cancel(cause) })
		if _, err := d.DialContext(ctx, "tcp", "x:1"); !errors.Is(err, context.Canceled) || errors.Is(err, cause) {
			t.Errorf("Dialer: %v", err)
		}
	})
}

// A dial whose handshake succeeded as ctx was canceled fails, closed.
func TestDialCancelRace(t *testing.T) {
	addr := listen(t, proxy{}.serve)
	for range 50 {
		ctx, cancel := context.WithCancel(t.Context())
		d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Trace: &socks0.ClientTrace{
			GotReply: func(wire.Reply, wire.Addr) { cancel() },
		}}}
		c, err := d.DialContext(ctx, "tcp", "example.com:80")
		switch {
		case err == nil:
			c.Close()
		case !errors.Is(err, context.Canceled):
			t.Fatalf("err = %v", err)
		}
	}
}

// Chaining: the second proxy is reached through the first; each hop runs the ctx trace.
func TestDialChain(t *testing.T) {
	got := make(chan request, 2)
	first := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve)}
	second := &socks0.Dialer{ProxyAddr: "second.example:1080", ProxyDial: first.DialContext}
	var (
		mu    sync.Mutex
		addrs []string
	)
	ctx := socks0.WithClientTrace(t.Context(), &socks0.ClientTrace{ConnectStart: func(_, a string) {
		mu.Lock()
		addrs = append(addrs, a)
		mu.Unlock()
	}})
	// The first proxy echoes: the greeting reads back as VER 5, method 1.
	_, err := second.DialContext(ctx, "tcp", "example.com:80")
	if req := <-got; req.target.String() != "second.example:1080" {
		t.Errorf("first proxy got %v", req.target)
	}
	if me, ok := errors.AsType[*socks0.MethodError](err); !ok || me.Selected != 1 {
		t.Errorf("err = %v", err)
	}
	if mu.Lock(); len(addrs) != 2 || addrs[0] != "second.example:1080" {
		t.Errorf("ConnectStart addrs %q", addrs)
	}
	mu.Unlock()
}

func TestDialNoGoroutineLeak(t *testing.T) {
	addr := listen(t, scripted([]byte{5, 0}, true))
	base := runtime.NumGoroutine()
	for i := range 60 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i%5)*time.Millisecond)
		d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: modes[i%3], ReplyTimeout: time.Millisecond}}
		if c, err := d.DialContext(ctx, "tcp", "example.com:80"); err == nil {
			if sc, ok := c.(*socks0.Conn); ok {
				sc.HandshakeContext(ctx)
			}
			c.Close()
		}
		cancel()
	}
	waitGoroutines(t, base+2) // server handlers may linger until their conns close
}

func openFDs(t *testing.T) int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		if es, err := os.ReadDir(dir); err == nil {
			return len(es)
		}
	}
	t.Skip("cannot count fds")
	return 0
}

// Failed UDP ASSOCIATE, BIND and RESOLVE leave no fd or goroutine behind.
func TestDialErrorsDoNotLeak(t *testing.T) {
	errDial := errors.New("relay dial refused by test")
	good := listenProxy(t)
	rep7 := listen(t, udpProxy{rep: wire.ReplyCommandNotSupported}.serve)
	port0 := listen(t, udpProxy{bnd: func(netip.AddrPort) wire.Addr { return mustAddr("127.0.0.1:0") }}.serve)
	unspec := listen(t, udpProxy{bnd: func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprint("0.0.0.0:", ap.Port())) }}.serve)
	hang := listen(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	bindEOF := listen(t, bind5(func(c net.Conn) { c.Write(reply(0, "127.0.0.1:5555")) }))
	tor := listen(t, answer([]byte{5, 4, 0, 0, 0, 0, 0, 0, 0, 0}, nil, false))
	for _, tc := range []struct {
		name  string
		d     *socks0.Dialer
		op    string // "dial", "listen packet", "bind" or "resolve"
		short bool   // under a 20 ms ctx
	}{
		{"REP 07", &socks0.Dialer{ProxyAddr: rep7}, "listen packet", false},
		{"BND port 0", &socks0.Dialer{ProxyAddr: port0}, "listen packet", false},
		{"RelayDial error", &socks0.Dialer{ProxyAddr: good, RelayDial: func(context.Context, string, string) (net.Conn, error) { return nil, errDial }}, "dial", false},
		{"RelayDial conn and error", &socks0.Dialer{ProxyAddr: good, RelayDial: func(ctx context.Context, n, a string) (net.Conn, error) {
			c, _ := new(net.Dialer).DialContext(ctx, n, a)
			return c, errDial
		}}, "dial", false},
		{"RelayListen conn and error", &socks0.Dialer{ProxyAddr: good, RelayListen: func(ctx context.Context, n, a string) (net.PacketConn, error) {
			c, _ := net.ListenPacket(n, a)
			return c, errDial
		}}, "listen packet", false},
		{"RelayDial nil, nil", &socks0.Dialer{ProxyAddr: good, RelayDial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}, "listen packet", false},
		{"substitution DNS failure", &socks0.Dialer{ProxyAddr: "no-such-host.invalid:1", ProxyDial: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, n, unspec)
		}}, "listen packet", false},
		{"ctx timeout in handshake", &socks0.Dialer{ProxyAddr: hang}, "listen packet", true},
		{"BIND EOF before reply 2", &socks0.Dialer{ProxyAddr: bindEOF}, "bind", false},
		{"BIND ctx timeout", &socks0.Dialer{ProxyAddr: hang}, "bind", true},
		{"RESOLVE REP 04", &socks0.Dialer{ProxyAddr: tor}, "resolve", false},
		{"RESOLVE timeout", &socks0.Dialer{ProxyAddr: hang}, "resolve", true},
	} {
		f := func(ctx context.Context) (err error) {
			if tc.short {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			switch tc.op {
			case "dial":
				_, err = tc.d.DialContext(ctx, "udp", "192.0.2.1:9")
			case "listen packet":
				_, err = tc.d.ListenPacket(ctx, "udp", "")
			case "bind":
				var ln net.Listener
				if ln, err = tc.d.Listen(ctx, "tcp", "192.0.2.1:1"); err == nil {
					_, err = ln.Accept()
				}
			case "resolve":
				_, err = tc.d.LookupHost(ctx, "nx.example")
			}
			return err
		}
		t.Run(tc.name, func(t *testing.T) {
			f(t.Context()) // warm up (resolver, listeners)
			time.Sleep(20 * time.Millisecond)
			runtime.GC()
			fds, gs := openFDs(t), runtime.NumGoroutine()
			for range 10 {
				if err := f(t.Context()); err == nil {
					t.Fatal("no error")
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				runtime.GC()
				nf, ng := openFDs(t), runtime.NumGoroutine()
				if nf <= fds && ng <= gs+1 {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("fds %d → %d, goroutines %d → %d", fds, nf, gs, ng)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// Config.HandshakeTimeout bounds the proxy dial and the handshake; 30 s by default.
func TestHandshakeTimeout(t *testing.T) {
	t.Run("ProxyDial ctx", func(t *testing.T) {
		errStop := errors.New("stop")
		dialOp := func(d *socks0.Dialer, ctx context.Context) error {
			_, err := d.DialContext(ctx, "tcp", "x.test:80")
			return err
		}
		for _, tc := range []struct {
			name string
			hst  time.Duration
			ctx  time.Duration // ctx deadline from now; zero: none
			want time.Duration // ProxyDial's ctx deadline from now; zero: none
			op   func(d *socks0.Dialer, ctx context.Context) error
		}{
			{name: "Dial", want: 30 * time.Second, op: dialOp},
			{name: "Dial ctx deadline kept", ctx: time.Hour, want: time.Hour, op: dialOp},
			{name: "Dial explicit", hst: 5 * time.Second, want: 5 * time.Second, op: dialOp},
			{name: "Dial explicit, earlier ctx", hst: 5 * time.Second, ctx: 2 * time.Second, want: 2 * time.Second, op: dialOp},
			{name: "Dial none", hst: -1, op: dialOp},
			{name: "Listen", want: 30 * time.Second, op: func(d *socks0.Dialer, ctx context.Context) error { _, err := d.Listen(ctx, "tcp", ""); return err }},
			{name: "ListenUDP", want: 30 * time.Second, op: func(d *socks0.Dialer, ctx context.Context) error { _, err := d.ListenUDP(ctx, "udp", ""); return err }},
			{name: "LookupNetIP", want: 30 * time.Second, op: func(d *socks0.Dialer, ctx context.Context) error {
				_, err := d.LookupNetIP(ctx, "ip", "x.test")
				return err
			}},
		} {
			for _, mode := range modes {
				var dl time.Time
				var has bool
				d := &socks0.Dialer{ProxyAddr: "proxy.test:1080", Config: &socks0.Config{Mode: mode, HandshakeTimeout: tc.hst},
					ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						dl, has = ctx.Deadline()
						return nil, errStop
					}}
				ctx := context.Background()
				if tc.ctx > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.ctx)
					defer cancel()
				}
				if err := tc.op(d, ctx); !errors.Is(err, errStop) {
					t.Fatalf("%s %v: %v", tc.name, mode, err)
				}
				if left := time.Until(dl); has != (tc.want > 0) || has && (left > tc.want || left < tc.want-5*time.Second) {
					t.Errorf("%s %v: ProxyDial ctx deadline in %v (set %v), want %v", tc.name, mode, left, has, tc.want)
				}
			}
		}
	})
	t.Run("tarpit", func(t *testing.T) {
		tarpit := listen(t, func(c net.Conn) { io.Copy(io.Discard, c) })
		within := func(name string, f func() error) {
			t.Helper()
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- f() }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) && socks0.KindOf(err) != socks0.KindTimeout {
					t.Errorf("%s: %v (kind %s), want a timeout", name, err, socks0.KindOf(err))
				}
				if el := time.Since(start); el > 3*time.Second {
					t.Errorf("%s: took %v", name, el)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: still blocked after 10 s", name)
			}
		}
		for _, mode := range modes {
			cfg := &socks0.Config{Mode: mode, HandshakeTimeout: 200 * time.Millisecond}
			d := &socks0.Dialer{ProxyAddr: tarpit, Config: cfg}
			within(fmt.Sprint("Dialer ", mode), func() error {
				c, err := d.Dial("tcp", "example.com:80")
				if err == nil { // ModeEarly: the reply wait, after the first Write
					defer c.Close()
					if _, err = c.Write([]byte("x")); err == nil {
						_, err = c.Read(make([]byte, 1))
					}
				}
				return err
			})
			for _, op := range []string{"Read", "Write", "HandshakeContext"} {
				if op == "Read" && mode == socks0.ModeEarly {
					continue // a Read before the first Write waits for it, by design
				}
				within(fmt.Sprint("Client ", mode, " ", op), func() error {
					nc, err := net.Dial("tcp", tarpit)
					if err != nil {
						return err
					}
					c := socks0.Client(nc, "example.com:80", cfg)
					defer c.Close()
					switch op {
					case "Read":
						_, err = c.Read(make([]byte, 1))
					case "Write":
						if _, err = c.Write([]byte("x")); err == nil {
							_, err = c.Read(make([]byte, 1)) // ModeEarly writes without waiting
						}
					default:
						err = c.HandshakeContext(context.Background())
					}
					return err
				})
			}
		}
		// ModeEarly: ReplyTimeout wins over HandshakeTimeout.
		d := &socks0.Dialer{ProxyAddr: tarpit, Config: &socks0.Config{Mode: socks0.ModeEarly, ReplyTimeout: 200 * time.Millisecond, HandshakeTimeout: time.Hour}}
		within("ReplyTimeout wins", func() error {
			c, err := d.Dial("tcp", "example.com:80")
			if err != nil {
				return err
			}
			defer c.Close()
			return c.(*socks0.Conn).HandshakeContext(context.Background())
		})
	})
}

// Nil, zero and huge inputs fail without panicking; a nil Dialer's methods fail as config errors.
func TestNoPanicOnBadInput(t *testing.T) {
	huge := strings.Repeat("a", 1<<20)
	bg := context.Background()
	for name, f := range map[string]func(){
		"zero Dialer": func() { (&socks0.Dialer{}).DialContext(bg, "tcp", "x:1") },
		//lint:ignore SA1012 a nil ctx must not panic
		"nil ctx":     func() { (&socks0.Dialer{ProxyAddr: "127.0.0.1:1"}).DialContext(nil, "tcp", "x:1") }, //nolint:staticcheck
		"empty args":  func() { (&socks0.Dialer{}).Dial("", "") },
		"huge target": func() { (&socks0.Dialer{}).Dial("tcp", huge+":80") },
		"huge proxy":  func() { (&socks0.Dialer{ProxyAddr: huge}).Dial("tcp", "x:80") },
		"256 name": func() {
			socks0.Client(newMem(), strings.Repeat("n", 256)+":1", nil).HandshakeContext(bg)
		},
		"zone target":      func() { socks0.Client(newMem(), "[fe80::1%en0]:1", nil).HandshakeContext(bg) },
		"huge mode":        func() { socks0.Client(newMem(), "x:1", &socks0.Config{Mode: 255}).HandshakeContext(bg) },
		"neg ReplyTimeout": func() { socks0.Client(newMem(goodReplies), "x:1", early(replyTimeout(-1))).HandshakeContext(bg) },
		"zero errors": func() {
			_ = (&socks0.HandshakeError{}).Error()
			(&socks0.HandshakeError{}).Timeout()
			_ = (&socks0.ReplyError{}).Error()
			errors.Is(&socks0.ReplyError{}, nil)
			_ = (&socks0.MethodError{}).Error()
			_ = (&socks0.AuthError{}).Error()
		},
		"zero ProxyURL":      func() { socks0.ParseProxyURL(&url.URL{Scheme: "socks5"}) },
		"WithClientTrace":    func() { socks0.WithClientTrace(bg, &socks0.ClientTrace{}) },
		"Mode String":        func() { _ = socks0.Mode(200).String() },
		"UserPass nil rw":    func() { socks0.UserPass{Username: huge}.Authenticate(bg, nil) },
		"UserPass ParseNil":  func() { socks0.UserPass{}.ParseReply(nil) },
		"Close twice nilcfg": func() { c := socks0.Client(newMem(), "x:1", nil); c.Close(); c.Close() },
	} {
		noPanic(t, name, f)
	}
	var d *socks0.Dialer
	ctx := t.Context()
	for name, f := range map[string]func() error{
		"Dial":            func() error { _, err := d.Dial("tcp", "example.com:80"); return err },
		"DialContext udp": func() error { _, err := d.DialContext(ctx, "udp", "192.0.2.1:53"); return err },
		"DialContext udp4": func() error {
			_, err := d.DialContext(ctx, "udp4", "192.0.2.1:53")
			return err
		},
		"ListenPacket": func() error { _, err := d.ListenPacket(ctx, "udp", ""); return err },
		"Listen":       func() error { _, err := d.Listen(ctx, "tcp", "192.0.2.1:21"); return err },
		"LookupNetIP":  func() error { _, err := d.LookupNetIP(ctx, "ip", "example.com"); return err },
		"LookupHost":   func() error { _, err := d.LookupHost(ctx, "example.com"); return err },
		"LookupAddr":   func() error { _, err := d.LookupAddr(ctx, "192.0.2.1"); return err },
	} {
		noPanic(t, "nil Dialer "+name, func() {
			if err := f(); socks0.KindOf(err) != socks0.KindConfig {
				t.Errorf("nil Dialer %s: %v, want a config error", name, err)
			}
		})
	}
}
