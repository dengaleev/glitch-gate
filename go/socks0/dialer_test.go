package socks0_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
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
					addr := listen(t, proxy{got: got}.serve)
					d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode, Auth: a.auth}}
					c, err := d.DialContext(t.Context(), "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					switch c.(type) {
					case *net.TCPConn:
						if mode == socks0.ModeEarly {
							t.Fatalf("conn is %T", c)
						}
					case *socks0.Conn:
						if mode != socks0.ModeEarly {
							t.Fatalf("conn is %T", c)
						}
					default:
						t.Fatalf("conn is %T", c)
					}
					msg := []byte("hello through the proxy")
					if _, err := c.Write(msg); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, len(msg))
					if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, msg) {
						t.Fatalf("echo = %q, %v", buf, err)
					}
					req := <-got
					want := request{methods: []wire.Method{wire.MethodNoAuth}, target: mustAddr(target)}
					if a.auth != nil {
						want.methods = []wire.Method{wire.MethodUserPass}
						if up, ok := a.auth.(socks0.UserPass); ok {
							want.user, want.pass = up.Username, up.Password
						}
					}
					if !reflect.DeepEqual(req, want) {
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

func TestDialWrites(t *testing.T) {
	auth := socks0.UserPass{Username: "u", Password: "p"}
	greet, _ := wire.AppendGreeting(nil, wire.MethodUserPass)
	up, _ := auth.AppendRequest(nil)
	req, _ := wire.AppendRequest(nil, wire.CmdConnect, mustAddr("example.com:80"))
	for _, tt := range []struct {
		mode socks0.Mode
		want [][]byte
	}{
		{socks0.ModeSequential, [][]byte{greet, up, req, []byte("data")}},
		{socks0.ModePipelined, [][]byte{slices.Concat(greet, up, req), []byte("data")}},
		{socks0.ModeEarly, [][]byte{slices.Concat(greet, up, req, []byte("data"))}},
	} {
		t.Run(tt.mode.String(), func(t *testing.T) {
			conns := make(chan *recConn, 1)
			d := &socks0.Dialer{
				ProxyAddr: listen(t, proxy{}.serve),
				ProxyDial: recDial(conns),
				Config:    &socks0.Config{Mode: tt.mode, Auth: auth},
			}
			c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			rc := <-conns
			if tt.mode != socks0.ModeEarly && c != net.Conn(rc) {
				t.Fatalf("DialContext returned %T, not the ProxyDial conn", c)
			}
			if _, err := c.Write([]byte("data")); err != nil {
				t.Fatal(err)
			}
			if writes, _, _ := rc.snapshot(); !reflect.DeepEqual(writes, tt.want) {
				t.Errorf("writes = % x\nwant     % x", writes, tt.want)
			}
		})
	}
}

func TestDialExactRead(t *testing.T) {
	tail := []byte("tunnel bytes right after the reply")
	for _, mode := range modes {
		for _, bound := range []wire.Addr{mustAddr("192.0.2.1:1"), mustAddr("[2001:db8::1]:2"), mustAddr("bound.example:3")} {
			for _, auth := range []socks0.Authenticator{nil, socks0.UserPass{Username: "u"}} {
				t.Run(mode.String()+"/"+bound.String(), func(t *testing.T) {
					conns := make(chan *recConn, 1)
					p := proxy{bound: bound, tail: tail, coalesce: mode != socks0.ModeSequential, after: func(c net.Conn) { io.Copy(io.Discard, c) }}
					d := &socks0.Dialer{
						ProxyAddr: listen(t, p.serve),
						ProxyDial: recDial(conns),
						Config:    &socks0.Config{Mode: mode, Auth: auth},
					}
					c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					rc := <-conns
					if mode == socks0.ModeEarly {
						if err := c.(*socks0.Conn).HandshakeContext(t.Context()); err != nil {
							t.Fatal(err)
						}
					}
					replies := 2 + 3 + len(mustBinary(bound))
					if auth != nil {
						replies += 2
					}
					if _, _, n := rc.snapshot(); n != replies {
						t.Errorf("handshake read %d bytes, replies are %d", n, replies)
					}
					buf := make([]byte, len(tail))
					if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, tail) {
						t.Errorf("tail = %q, %v", buf, err)
					}
				})
			}
		}
	}
}

func mustBinary(a wire.Addr) []byte {
	b, err := a.AppendBinary(nil)
	if err != nil {
		panic(err)
	}
	return b
}

// net.Pipe: each server message in its own Read, the reply byte by byte.
func TestDialPipelinedReads(t *testing.T) {
	var events []string
	gotMethod := make(chan struct{})
	trace := &socks0.ClientTrace{
		GotMethod: func(wire.Method) { events = append(events, "method"); close(gotMethod) },
		AuthDone:  func(error) { events = append(events, "auth") },
		GotReply:  func(wire.Reply, wire.Addr) { events = append(events, "reply") },
	}
	reply, _ := wire.AppendReply(nil, 0, mustAddr("bound.example:1"))
	handle := func(s net.Conn) {
		s.Read(make([]byte, 1024))
		s.Write([]byte{5, 2})
		<-gotMethod // before the rest is sent
		s.Write([]byte{1, 0})
		for _, b := range reply {
			s.Write([]byte{b})
		}
		s.Write([]byte("tail"))
	}
	pd := pipeDial(t, handle)
	total := 2 + 2 + len(reply)
	d := &socks0.Dialer{
		ProxyDial: func(ctx context.Context, n, a string) (net.Conn, error) {
			c, err := pd(ctx, n, a)
			return &recConn{Conn: c, limit: total}, err
		},
		Config: &socks0.Config{Auth: socks0.UserPass{}, Trace: trace},
	}
	c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc := c.(*recConn)
	_, reads, n := rc.snapshot()
	if n != total || rc.over || reads[0] != 2+2+5 {
		t.Errorf("read %d bytes of %d in reads asking %v", n, total, reads)
	}
	if !slices.Equal(events, []string{"method", "auth", "reply"}) {
		t.Errorf("events = %v", events)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "tail" {
		t.Errorf("tail = %q, %v", buf, err)
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			var dialed atomic.Bool
			d := &socks0.Dialer{
				ProxyAddr: "192.0.2.1:1080",
				ProxyDial: func(context.Context, string, string) (net.Conn, error) {
					dialed.Store(true)
					return nil, errTest
				},
				Config: tt.cfg,
			}
			c, err := d.DialContext(t.Context(), tt.network, tt.addr)
			if c != nil || dialed.Load() {
				t.Fatalf("conn %v, dialed %v", c, dialed.Load())
			}
			if he := handshakeErrOf(t, err); he.Stage != socks0.StageConfig {
				t.Errorf("stage %q", he.Stage)
			}
			if k := socks0.KindOf(err); k != socks0.KindConfig {
				t.Errorf("KindOf = %q", k)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v; want it to match %v", err, tt.is)
			}
			if strings.Contains(err.Error(), long) {
				t.Errorf("err holds the credential: %v", err)
			}
			t.Log(err)
		})
	}
	var d *socks0.Dialer
	if _, err := d.Dial("tcp", "example.com:80"); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("nil Dialer: %v", err)
	}
}

// interactive is an Authenticator that is not a Pipeliner.
type interactive struct{ m wire.Method }

func (a interactive) Method() wire.Method { return a.m }

func (a interactive) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	if _, err := rw.Write([]byte{1, 'x'}); err != nil {
		return err
	}
	var b [1]byte
	if _, err := io.ReadFull(rw, b[:]); err != nil {
		return err
	}
	if b[0] != 0 {
		return errors.Join(socks0.ErrAuthFailed, errTest)
	}
	return nil
}

// pipeliner: request "P", reply "ok!" padded to size bytes, or a rejection.
type pipeliner struct {
	reqErr error
	size   int
}

func (pipeliner) Method() wire.Method { return 0x80 }

func (pipeliner) Authenticate(context.Context, io.ReadWriter) error { return errTest }

func (p pipeliner) AppendRequest(dst []byte) ([]byte, error) {
	if p.reqErr != nil {
		return dst, p.reqErr
	}
	return append(dst, 'P'), nil
}

func (p pipeliner) ParseReply(b []byte) (int, error) {
	n := max(p.size, 3)
	switch {
	case len(b) < 3:
		return 3, wire.ErrIncomplete
	case string(b[:3]) != "ok!":
		return 0, errors.Join(socks0.ErrAuthFailed, errTest)
	case len(b) < n:
		return n, wire.ErrIncomplete
	}
	return n, nil
}

func TestCustomAuth(t *testing.T) {
	serve := func(authReply string, n int) func(net.Conn) {
		return func(c net.Conn) {
			if _, err := wire.ReadGreeting(c); err != nil {
				return
			}
			c.Write([]byte{5, 0x80})
			io.ReadFull(c, make([]byte, n))
			c.Write([]byte(authReply))
			if _, _, err := wire.ReadRequest(c); err != nil {
				return
			}
			reply, _ := wire.AppendReply(nil, 0, defaultBound)
			c.Write(append(reply, "tail"...))
			io.Copy(io.Discard, c)
		}
	}
	for _, tt := range []struct {
		name  string
		mode  socks0.Mode
		auth  socks0.Authenticator
		srv   func(net.Conn)
		stage string
	}{
		{"pipelined", socks0.ModePipelined, pipeliner{}, serve("ok!", 1), ""},
		{"long reply", socks0.ModePipelined, pipeliner{size: 1000}, serve("ok!"+strings.Repeat(".", 997), 1), ""},
		{"too long reply", socks0.ModePipelined, pipeliner{size: 100 << 10}, serve("ok!", 1), socks0.StageAuth},
		{"pipelined rejected", socks0.ModePipelined, pipeliner{}, serve("no!", 1), socks0.StageAuth},
		{"early", socks0.ModeEarly, pipeliner{}, serve("ok!", 1), ""},
		{"sequential", socks0.ModeSequential, interactive{0x80}, serve("\x00", 2), ""},
		{"sequential rejected", socks0.ModeSequential, interactive{0x80}, serve("\x01", 2), socks0.StageAuth},
		{"sequential eof", socks0.ModeSequential, interactive{0x80}, scripted([]byte{5, 0x80}, false), socks0.StageAuth},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var authDone []error
			cfg := &socks0.Config{Mode: tt.mode, Auth: tt.auth, Trace: &socks0.ClientTrace{
				AuthDone: func(err error) { authDone = append(authDone, err) },
			}}
			d := &socks0.Dialer{ProxyAddr: listen(t, tt.srv), Config: cfg}
			err := handshakeErr(t.Context(), d, "example.com:80")
			if len(authDone) != 1 || !errors.Is(err, authDone[0]) {
				t.Errorf("AuthDone ran with %v; err %v", authDone, err)
			}
			if tt.stage == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if he := handshakeErrOf(t, err); he.Stage != tt.stage {
				t.Errorf("stage %q, err %v", he.Stage, err)
			}
		})
	}
}

func TestDialRejectedAuthStage(t *testing.T) {
	for _, mode := range modes {
		d := &socks0.Dialer{
			ProxyAddr: listen(t, proxy{status: 1}.serve),
			Config:    &socks0.Config{Mode: mode, Auth: socks0.UserPass{Username: "u", Password: "secret"}},
		}
		err := handshakeErr(t.Context(), d, "example.com:80")
		he := handshakeErrOf(t, err)
		ae, ok := errors.AsType[*socks0.AuthError](err)
		if he.Stage != wire.StageUserPassStatus || !ok || ae.Status != 1 || !errors.Is(err, socks0.ErrAuthFailed) || socks0.KindOf(err) != socks0.KindAuth {
			t.Errorf("%v: %v (stage %q)", mode, err, he.Stage)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("error holds the password: %v", err)
		}
	}
}

type fakeResolver struct {
	ips  []netip.Addr
	err  error
	nets chan string
}

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.nets <- network + " " + host
	return r.ips, r.err
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
		r := fakeResolver{ips: tt.ips, nets: make(chan string, 1)}
		d := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve), Resolver: r}
		c, err := d.DialContext(t.Context(), tt.network, "example.com:80")
		if l := <-r.nets; l != tt.lookup+" example.com" {
			t.Errorf("%s: lookup %q", tt.network, l)
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
	r := fakeResolver{err: errTest, nets: make(chan string, 1)}
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve), Resolver: r}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); !errors.Is(err, errTest) {
		t.Errorf("err = %v", err)
	}
	<-r.nets
	c, err := d.DialContext(t.Context(), "tcp", "192.0.2.1:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
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
	op := err.(*net.OpError)
	if op.Net != "tcp" || op.Source.String() != addr || op.Addr.String() != "example.com:80" {
		t.Errorf("OpError = %+v", op)
	}

	d = &socks0.Dialer{ProxyDial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); handshakeErrOf(t, err).Stage != socks0.StageProxyDial {
		t.Errorf("nil conn: %v", err)
	}
}

func TestDialClearsDeadlines(t *testing.T) {
	for _, mode := range modes {
		conns := make(chan *recConn, 1)
		rd := recDial(conns)
		d := &socks0.Dialer{
			ProxyAddr: listen(t, proxy{}.serve),
			ProxyDial: func(ctx context.Context, n, a string) (net.Conn, error) {
				c, err := rd(ctx, n, a)
				if err == nil {
					c.SetDeadline(time.Now().Add(time.Hour))
				}
				return c, err
			},
			Config: &socks0.Config{Mode: mode},
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		c, err := d.DialContext(ctx, "tcp", "example.com:80")
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		rc := <-conns
		rc.mu.Lock()
		last := rc.dls[len(rc.dls)-1]
		rc.mu.Unlock()
		if !last.IsZero() {
			t.Errorf("%v: last deadline %v", mode, last)
		}
		if _, err := c.Write([]byte("x")); err != nil {
			t.Errorf("%v: write after cancel: %v", mode, err)
		}
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Errorf("%v: read after cancel: %v", mode, err)
		}
		c.Close()
	}
}

func TestDialCancel(t *testing.T) {
	methodThenSilence := scripted([]byte{5, 0}, true)
	authThenSilence := scripted([]byte{5, 2, 1, 0}, true)
	for _, tt := range []struct {
		name  string
		srv   func(net.Conn)
		auth  socks0.Authenticator
		modes []socks0.Mode
		stage string
	}{
		{"silent", scripted(nil, true), nil, modes[:2], wire.StageMethodSelection},
		{"method only", methodThenSilence, nil, modes[:2], wire.StageReply},
		{"auth only", authThenSilence, socks0.UserPass{}, modes[1:2], wire.StageReply},
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

	// Already canceled: fails before the dial completes.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve)}
	if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled ctx: %v", err)
	}
	// A ProxyDial ignoring ctx: cancellation still wins.
	d.ProxyDial = func(context.Context, string, string) (net.Conn, error) { return nil, errTest }
	if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled ctx, custom ProxyDial: %v", err)
	}
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

func TestDialChain(t *testing.T) {
	got := make(chan request, 2)
	first := &socks0.Dialer{ProxyAddr: listen(t, proxy{got: got}.serve)}
	second := &socks0.Dialer{ProxyAddr: "second.example:1080", ProxyDial: first.DialContext}
	// The first proxy echoes: the greeting reads back as VER 5, method 1.
	_, err := second.DialContext(t.Context(), "tcp", "example.com:80")
	if req := <-got; req.target.String() != "second.example:1080" {
		t.Errorf("first proxy got %v", req.target)
	}
	if me, ok := errors.AsType[*socks0.MethodError](err); !ok || me.Selected != 1 {
		t.Errorf("err = %v", err)
	}
}
