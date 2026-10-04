package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestVerifyKindOfTypedNil(t *testing.T) {
	for name, err := range map[string]error{
		"*HandshakeError(nil)":                (*socks0.HandshakeError)(nil),
		"*ReplyError(nil)":                    (*socks0.ReplyError)(nil),
		"*MethodError(nil)":                   (*socks0.MethodError)(nil),
		"*AuthError(nil)":                     (*socks0.AuthError)(nil),
		"*ProtocolError(nil)":                 (*socks0.ProtocolError)(nil),
		"HandshakeError{Err: nil}":            &socks0.HandshakeError{Stage: "x"},
		"HandshakeError{Err: (*ReplyError)0}": &socks0.HandshakeError{Stage: "x", Err: (*socks0.ReplyError)(nil)},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("KindOf(%s) panics: %v", name, r)
				}
			}()
			socks0.KindOf(err)
		}()
	}
}

func TestVerifyParseProxyURL(t *testing.T) {
	for _, tt := range []struct {
		raw      string
		addr     string
		local    bool
		tls      bool
		auth     *socks0.UserPass
		wantErr  bool
		noSecret string
	}{
		{raw: "socks5://h", addr: "h:1080", local: true},
		{raw: "socks5h://h:1", addr: "h:1"},
		{raw: "SOCKS5H://h:2", addr: "h:2"},
		{raw: "socks5://[::1]", addr: "[::1]:1080", local: true},
		{raw: "socks5h://[2001:db8::1]:9050", addr: "[2001:db8::1]:9050"},
		{raw: "socks5://h:65535", addr: "h:65535", local: true},
		{raw: "socks5://h:0", wantErr: true},
		{raw: "socks5://h:65536", wantErr: true},
		{raw: "socks5://h:99999999999999999999", wantErr: true},
		{raw: "socks5://:1080", wantErr: true},
		{raw: "socks5:///path", wantErr: true},
		{raw: "socks4://h", addr: "h:1080", local: true},
		{raw: "socks4a://h", addr: "h:1080"},
		{raw: "http://h", wantErr: true},
		{raw: "socks://h", wantErr: true},
		{raw: "h:1080", wantErr: true},
		{raw: "socks5s://h", addr: "h:1080", tls: true},
		{raw: "socks5+tls://h:443", addr: "h:443", tls: true},
		{raw: "socks5h+tls://h", addr: "h:1080", tls: true},
		{raw: "socks5://u:p%40ss%3Aw@h", addr: "h:1080", local: true, auth: &socks0.UserPass{Username: "u", Password: "p@ss:w"}},
		{raw: "socks5://%75ser@h", addr: "h:1080", local: true, auth: &socks0.UserPass{Username: "user"}},
		{raw: "socks5://@h", addr: "h:1080", local: true, auth: &socks0.UserPass{}},
		{raw: "socks5://:@h", addr: "h:1080", local: true, auth: &socks0.UserPass{}},
		{raw: "socks5://h/ignored?q=1#f", addr: "h:1080", local: true},
		{raw: "socks5://u:" + strings.Repeat("P", 256) + "@h", wantErr: true, noSecret: strings.Repeat("P", 256)},
		{raw: "socks5://" + strings.Repeat("U", 256) + ":topsecret@h", wantErr: true, noSecret: "topsecret"},
		{raw: "ftp://u:topsecret@h", wantErr: true, noSecret: "topsecret"},
		{raw: "socks5://u:topsecret@h:0", wantErr: true, noSecret: "topsecret"},
		{raw: "socks5://u:topsecret@:1", wantErr: true, noSecret: "topsecret"},
	} {
		u, err := url.Parse(tt.raw)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%s: url.Parse: %v", tt.raw, err)
			}
			continue
		}
		p, err := socks0.ParseProxyURL(u)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: no error (%+v)", tt.raw, p)
			} else if tt.noSecret != "" && strings.Contains(err.Error(), tt.noSecret) {
				t.Errorf("%s: error leaks the secret: %v", tt.raw, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tt.raw, err)
			continue
		}
		if p.Addr != tt.addr || p.ResolveLocally != tt.local || p.TLS != tt.tls {
			t.Errorf("%s: %+v", tt.raw, p)
		}
		switch a := p.Config.Auth.(type) {
		case nil:
			if tt.auth != nil {
				t.Errorf("%s: no auth", tt.raw)
			}
		case socks0.UserPass:
			if tt.auth == nil || a != *tt.auth {
				t.Errorf("%s: auth %+v", tt.raw, a)
			}
		default:
			t.Errorf("%s: auth %T", tt.raw, a)
		}
		d, err := socks0.FromURL(u)
		if err != nil {
			t.Fatal(err)
		}
		if (d.Resolver != nil) != tt.local || (d.ProxyDial != nil) != tt.tls || d.ProxyAddr != tt.addr {
			t.Errorf("%s: FromURL resolver %v tls %v addr %s", tt.raw, d.Resolver != nil, d.ProxyDial != nil, d.ProxyAddr)
		}
	}
	if _, err := socks0.ParseProxyURL(&url.URL{}); err == nil {
		t.Error("empty URL")
	}
	if _, err := socks0.ParseProxyURL(nil); err == nil {
		t.Error("nil URL")
	}
	if _, err := socks0.FromURL(nil); err == nil {
		t.Error("FromURL(nil)")
	}
}

func TestVerifyParseProxyURLPortForm(t *testing.T) {
	u, _ := url.Parse("socks5h://h:0080")
	p, err := socks0.ParseProxyURL(u)
	if err != nil {
		t.Fatal(err)
	}
	if p.Addr != "h:80" {
		t.Errorf("Addr = %q, want h:80", p.Addr)
	}
	for _, raw := range []string{"socks5://topuser:pw@h:0", "socks5:topuser:pw@h:1"} {
		u, _ := url.Parse(raw)
		if _, err := socks0.ParseProxyURL(u); err == nil || strings.Contains(err.Error(), "topuser") {
			t.Errorf("%s: error %v shows the user name", raw, err)
		}
	}
}

type traceLog struct {
	mu  sync.Mutex
	evs []string
}

func (l *traceLog) add(s string) { l.mu.Lock(); l.evs = append(l.evs, s); l.mu.Unlock() }
func (l *traceLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.evs)
}

func (l *traceLog) trace() *socks0.ClientTrace {
	e := func(err error) string {
		if err != nil {
			return " err"
		}
		return ""
	}
	return &socks0.ClientTrace{
		ConnectStart:   func(string, string) { l.add("ConnectStart") },
		ConnectDone:    func(_, _ string, err error) { l.add("ConnectDone" + e(err)) },
		WroteHandshake: func(err error) { l.add("WroteHandshake" + e(err)) },
		GotMethod:      func(wire.Method) { l.add("GotMethod") },
		AuthDone:       func(err error) { l.add("AuthDone" + e(err)) },
		GotReply:       func(wire.Reply, wire.Addr) { l.add("GotReply") },
		HandshakeDone:  func(err error) { l.add("HandshakeDone" + e(err)) },
	}
}

// Byte-by-byte server; HandshakeDone iff WroteHandshake.
func TestVerifyTraceOrderPerMode(t *testing.T) {
	ok := []string{"ConnectStart", "ConnectDone", "WroteHandshake", "GotMethod", "AuthDone", "GotReply", "HandshakeDone"}
	for _, tt := range []struct {
		name string
		srv  []byte
		eof  bool
		want []string
	}{
		{"ok", serverMsgs(true, "192.0.2.1:1"), false, ok},
		{"method", []byte{5, 0xFF}, true, []string{"ConnectStart", "ConnectDone", "WroteHandshake", "GotMethod", "HandshakeDone err"}},
		{"eof at method", nil, true, []string{"ConnectStart", "ConnectDone", "WroteHandshake", "HandshakeDone err"}},
		{"auth eof", []byte{5, 2}, true, []string{"ConnectStart", "ConnectDone", "WroteHandshake", "GotMethod", "AuthDone err", "HandshakeDone err"}},
		{"auth rejected", []byte{5, 2, 1, 1}, true, []string{"ConnectStart", "ConnectDone", "WroteHandshake", "GotMethod", "AuthDone err", "HandshakeDone err"}},
		{"reply refused", append([]byte{5, 2, 1, 0}, reply(5, "0.0.0.0:0")...), true, []string{"ConnectStart", "ConnectDone", "WroteHandshake", "GotMethod", "AuthDone", "GotReply", "HandshakeDone err"}},
		{"reply truncated REP 0", []byte{5, 2, 1, 0, 5, 0, 0, 1}, true, []string{"ConnectStart", "ConnectDone", "WroteHandshake", "GotMethod", "AuthDone", "HandshakeDone err"}},
	} {
		for _, mode := range modes {
			for _, viaDialer := range []bool{true, false} {
				var l traceLog
				mc := newMem(tt.srv)
				mc.chunk = 1
				if tt.eof {
					mc.closeServer()
				}
				c, _ := hsRun(t, mc, mode, upAuth, viaDialer, l.trace())
				if c != nil {
					c.Close()
				}
				want := tt.want
				if !viaDialer {
					want = want[2:]
				}
				if got := l.get(); !slices.Equal(got, want) {
					t.Errorf("%s/%v/dialer=%v:\n got %q\nwant %q", tt.name, mode, viaDialer, got, want)
				}
			}
		}
	}
}

func TestVerifyNoPanicInputs(t *testing.T) {
	huge := strings.Repeat("a", 1<<20)
	calls := map[string]func(){
		"zero Dialer": func() { (&socks0.Dialer{}).DialContext(context.Background(), "tcp", "x:1") },
		//lint:ignore SA1012 a nil ctx must not panic
		"nil ctx":     func() { (&socks0.Dialer{ProxyAddr: "127.0.0.1:1"}).DialContext(nil, "tcp", "x:1") }, //nolint:staticcheck
		"empty args":  func() { (&socks0.Dialer{}).Dial("", "") },
		"huge target": func() { (&socks0.Dialer{}).Dial("tcp", huge+":80") },
		"huge proxy":  func() { (&socks0.Dialer{ProxyAddr: huge}).Dial("tcp", "x:80") },
		"256 name": func() {
			socks0.Client(newMem(), strings.Repeat("n", 256)+":1", nil).HandshakeContext(context.Background())
		},
		"zone target": func() { socks0.Client(newMem(), "[fe80::1%en0]:1", nil).HandshakeContext(context.Background()) },
		"huge mode": func() {
			socks0.Client(newMem(), "x:1", &socks0.Config{Mode: 255}).HandshakeContext(context.Background())
		},
		"neg ReplyTimeout": func() {
			socks0.Client(newMem(goodReplies), "x:1", early(func(c *socks0.Config) { c.ReplyTimeout = -1 })).HandshakeContext(context.Background())
		},
		"zero HandshakeErr":  func() { _ = (&socks0.HandshakeError{}).Error(); (&socks0.HandshakeError{}).Timeout() },
		"zero ReplyError":    func() { _ = (&socks0.ReplyError{}).Error(); errors.Is(&socks0.ReplyError{}, nil) },
		"zero MethodError":   func() { _ = (&socks0.MethodError{}).Error() },
		"zero AuthError":     func() { _ = (&socks0.AuthError{}).Error() },
		"zero ProxyURL":      func() { socks0.ParseProxyURL(&url.URL{Scheme: "socks5"}) },
		"WithClientTrace":    func() { socks0.WithClientTrace(context.Background(), &socks0.ClientTrace{}) },
		"Mode String":        func() { _ = socks0.Mode(200).String() },
		"UserPass nil rw":    func() { socks0.UserPass{Username: huge}.Authenticate(context.Background(), nil) },
		"UserPass ParseNil":  func() { socks0.UserPass{}.ParseReply(nil) },
		"Close twice nilcfg": func() { c := socks0.Client(newMem(), "x:1", nil); c.Close(); c.Close() },
	}
	for name, f := range calls {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panics: %v", name, r)
				}
			}()
			f()
		}()
	}
}

func TestVerifyNoPasswordAnywhere(t *testing.T) {
	const pw = "PW-7c1f5e"
	auth := socks0.UserPass{Username: "alice", Password: pw}
	var seen []string
	var mu sync.Mutex
	note := func(s string) { mu.Lock(); seen = append(seen, s); mu.Unlock() }
	tr := &socks0.ClientTrace{
		ConnectDone:    func(n, a string, err error) { note(fmt.Sprint(n, a, err)) },
		WroteHandshake: func(err error) { note(fmt.Sprint(err)) },
		AuthDone:       func(err error) { note(fmt.Sprint(err)) },
		HandshakeDone:  func(err error) { note(fmt.Sprint(err)) },
	}
	scripts := [][]byte{nil, {5}, {5, 2}, {5, 2, 1}, {5, 2, 1, 1}, {5, 2, 5, 1}, {5, 2, 1, 0, 5, 1}, []byte("HTTP/1.1 407"), {5, 0xFF}, {5, 0}}
	for _, s := range scripts {
		for _, mode := range modes {
			for _, viaDialer := range []bool{true, false} {
				mc := newMem(s)
				mc.closeServer()
				c, err := hsRun(t, mc, mode, auth, viaDialer, tr)
				if c != nil {
					c.Close()
				}
				note(fmt.Sprintf("%v|%+v|%s", err, err, err))
				if err != nil {
					for e := err; e != nil; e = errors.Unwrap(e) {
						note(e.Error())
					}
				}
			}
		}
	}
	// Write failure mid-auth (L0) and config errors.
	mc := newMem([]byte{5, 2})
	mc.onWrite = func(b []byte) (int, error) {
		if len(b) > 3 {
			return 1, errors.New("write failed")
		}
		return len(b), nil
	}
	_, err := hsRun(t, mc, socks0.ModeSequential, auth, true, tr)
	note(fmt.Sprint(err))
	_, err = (&socks0.Dialer{Config: &socks0.Config{Auth: socks0.UserPass{Username: "u", Password: pw + strings.Repeat("x", 300)}}}).Dial("tcp", "x:1")
	note(fmt.Sprint(err))
	for _, s := range seen {
		if strings.Contains(s, pw) {
			t.Errorf("password leaked: %s", s)
		}
	}
}

// Handshake written, data not: a short count and a data error, not a handshake error.
func TestVerifyEarlyWriteDataFailure(t *testing.T) {
	hsLen := len(hsNoAuth)
	mc := newMem(goodReplies)
	mc.onWrite = func(b []byte) (int, error) {
		if len(b) > hsLen {
			return hsLen + 1, errTest
		}
		return len(b), nil
	}
	c := socks0.Client(mc, "example.com:80", early())
	n, err := c.Write([]byte("abc"))
	if n != 1 || !errors.Is(err, errTest) || isHandshakeErr(err) {
		t.Errorf("Write = %d, %v", n, err)
	}
	if err := c.HandshakeContext(context.Background()); err != nil {
		t.Errorf("handshake = %v", err)
	}
}

var _ = io.EOF

// Hooks may call the Conn's non-handshake methods without deadlocking.
func TestVerifyHooksReenter(t *testing.T) {
	for _, mode := range modes {
		var c *socks0.Conn
		poke := func() {
			if c != nil {
				c.BoundAddr()
				c.SetDeadline(time.Now().Add(time.Second))
				c.LocalAddr()
			}
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
		// Close from a hook fails the handshake cleanly.
		var c2 *socks0.Conn
		tr2 := &socks0.ClientTrace{GotMethod: func(wire.Method) { c2.Close() }}
		c2 = socks0.Client(newMem(serverMsgs(false, "192.0.2.1:1")), "x:1", &socks0.Config{Mode: mode, Trace: tr2})
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

func FuzzVerifyParseProxyURL(f *testing.F) {
	for _, s := range []string{"socks5://u:secretpw@h:1", "socks5h://[::1]:9050", "socks5s://h", "x://u:pw@", "socks5://u:longsecret@h:0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		p, err := socks0.ParseProxyURL(u)
		if err == nil {
			if p.Addr == "" {
				t.Fatalf("%q: empty Addr", raw)
			}
			return
		}
		if u.User != nil {
			if pw, ok := u.User.Password(); ok && len(pw) >= 6 && !strings.Contains(u.Redacted(), pw) && strings.Contains(err.Error(), pw) {
				t.Fatalf("%q: error leaks the password: %v", raw, err)
			}
		}
	})
}

// url.Parse accepts hosts like "]0"; ParseProxyURL must not return an unusable Addr.
func TestVerifyParseProxyURLBadHostAccepted(t *testing.T) {
	u, err := url.Parse("socks5://]0")
	if err != nil {
		t.Skip(err)
	}
	p, err := socks0.ParseProxyURL(u)
	if err == nil {
		if _, _, err := net.SplitHostPort(p.Addr); err != nil {
			t.Errorf("accepted host %q gives unusable Addr %q: %v", u.Host, p.Addr, err)
		}
	}
}

// SetDeadline is a no-op (some muxes): cancellation closes the conn, as crypto/tls.
func TestVerifyCancelWithoutDeadlineSupport(t *testing.T) {
	for _, mode := range modes {
		mc := newMem()
		mc.ignoreDeadlines = true
		c := socks0.Client(mc, "x:1", &socks0.Config{Mode: mode})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- c.HandshakeContext(ctx) }()
		select {
		case err := <-done:
			t.Logf("%v: returned %v", mode, err)
		case <-time.After(500 * time.Millisecond):
			t.Errorf("%v: HandshakeContext still blocked 480 ms after its ctx expired (conn without deadlines)", mode)
			c.Close()
			mc.closeServer()
			<-done
		}
		cancel()
	}
}

func TestVerifySpecGaps(t *testing.T) {
	t.Run("first Write: handshake + 32 KiB, then the rest", func(t *testing.T) {
		mc := newMem(goodReplies)
		c := socks0.Client(mc, "example.com:80", early())
		data := make([]byte, 40<<10)
		if n, err := c.Write(data); n != len(data) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
		_, _, writes, _ := mc.stats()
		if len(writes) != 2 || len(writes[0]) != len(hsNoAuth)+32<<10 || len(writes[1]) != 8<<10 {
			t.Errorf("writes %d: %d, ...", len(writes), len(writes[0]))
		}
	})
	t.Run("cancellation wraps ctx.Err(), not context.Cause", func(t *testing.T) {
		cause := errors.New("my cause")
		for _, mode := range modes {
			c := socks0.Client(newMem([]byte{5, 0}), "x:1", &socks0.Config{Mode: mode})
			ctx, cancel := context.WithCancelCause(context.Background())
			time.AfterFunc(10*time.Millisecond, func() { cancel(cause) })
			err := c.HandshakeContext(ctx)
			if !errors.Is(err, context.Canceled) || errors.Is(err, cause) {
				t.Errorf("%v: %v", mode, err)
			}
		}
		mc := newMem([]byte{5, 0})
		d := &socks0.Dialer{ProxyAddr: "p:1", ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
		ctx, cancel := context.WithCancelCause(context.Background())
		time.AfterFunc(10*time.Millisecond, func() { cancel(cause) })
		if _, err := d.DialContext(ctx, "tcp", "x:1"); !errors.Is(err, context.Canceled) || errors.Is(err, cause) {
			t.Errorf("Dialer: %v", err)
		}
	})
	t.Run("Client OpError: Net tcp, Source RemoteAddr, Addr target", func(t *testing.T) {
		mc := newMem([]byte{5, 0xFF})
		c := socks0.Client(mc, "example.com:80", nil)
		err := c.HandshakeContext(context.Background())
		op, ok := err.(*net.OpError)
		if !ok || op.Net != "tcp" || op.Source == nil || op.Source.String() != "proxy" || op.Addr == nil || op.Addr.String() != "example.com:80" {
			t.Errorf("%#v", err)
		}
	})
	t.Run("CloseWrite bounded by ReplyTimeout", func(t *testing.T) {
		raw, err := net.Dial("tcp", listen(t, scripted(nil, true)))
		if err != nil {
			t.Fatal(err)
		}
		c := socks0.Client(raw, "x:1", early(func(c *socks0.Config) { c.ReplyTimeout = 20 * time.Millisecond }))
		defer c.Close()
		done := make(chan error, 1)
		go func() { done <- c.CloseWrite() }()
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("CloseWrite = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("CloseWrite not bounded by ReplyTimeout")
		}
	})
	t.Run("chain: every hop runs the ctx trace", func(t *testing.T) {
		var mu sync.Mutex
		var addrs []string
		ctx := socks0.WithClientTrace(t.Context(), &socks0.ClientTrace{ConnectStart: func(_, a string) {
			mu.Lock()
			addrs = append(addrs, a)
			mu.Unlock()
		}})
		first := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve)}
		second := &socks0.Dialer{ProxyAddr: "second.example:1080", ProxyDial: first.DialContext}
		second.DialContext(ctx, "tcp", "example.com:80")
		if len(addrs) != 2 || addrs[0] != "second.example:1080" {
			t.Errorf("ConnectStart addrs %q", addrs)
		}
	})
	t.Run("HandshakeContext not starting the handshake: its ctx trace unused", func(t *testing.T) {
		var l traceLog
		mc := newMem(goodReplies)
		c := socks0.Client(mc, "x:1", early())
		c.Write([]byte("x"))
		if err := c.HandshakeContext(socks0.WithClientTrace(t.Context(), l.trace())); err != nil {
			t.Fatal(err)
		}
		if got := l.get(); len(got) != 0 {
			t.Errorf("hooks ran: %q", got)
		}
	})
}
