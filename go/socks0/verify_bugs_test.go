package socks0_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var goodReplies = append([]byte{5, 0}, reply(0, "192.0.2.1:1080")...)

// The server replies before reading the request, so the early Write fails
// after 2 bytes.
func TestVerifyBugEarlyWriteFailsAfterRepliesReturnsNilError(t *testing.T) {
	c0 := newMem(goodReplies)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c0.onWrite = func(b []byte) (int, error) {
		once.Do(func() { close(started) })
		<-release
		return 2, errTest
	}
	c := socks0.Client(c0, "example.com:80", early())
	defer c.Close()
	type res struct {
		n   int
		err error
	}
	wc := make(chan res)
	go func() { n, err := c.Write([]byte("data")); wc <- res{n, err} }()
	<-started
	if err := c.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("HandshakeContext = %v", err)
	}
	close(release)
	r := <-wc
	if r.n < 4 && r.err == nil {
		t.Errorf("Write = (%d, nil): short write without an error; the 4 data bytes were never sent", r.n)
	}
	// Logged only: the handshake never fully reached the proxy.
	n, err := c.Write([]byte("more"))
	t.Logf("next Write = %d, %v; wire = %q", n, err, c0.written())
}

// Close racing the reply reader's stage update (-race), over TCP.
func TestVerifyBugRaceRstageTCP(t *testing.T) {
	for range 50 {
		c, _ := client(t, scripted(nil, true), early())
		c.Write(nil)
		rd := make(chan error)
		go func() { _, err := c.Read(make([]byte, 1)); rd <- err }()
		time.Sleep(2 * time.Millisecond)
		c.Close()
		c.HandshakeContext(t.Context())
		<-rd
	}
}

// AfterFunc runs in a new goroutine: an instant handshake could beat the
// pre-canceled ctx.
func TestVerifyBugHandshakeContextPrecanceledSucceeds(t *testing.T) {
	for _, mode := range modes {
		var ok atomic.Int32
		const runs = 300
		for range runs {
			c := socks0.Client(newMem(goodReplies), "example.com:80", &socks0.Config{Mode: mode})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := c.HandshakeContext(ctx); err == nil {
				ok.Add(1)
			}
			c.Close()
		}
		if n := ok.Load(); n > 0 {
			t.Errorf("%v: HandshakeContext(canceled ctx) returned nil in %d/%d runs", mode, n, runs)
		}
	}
}

func TestVerifyDialPrecanceledAlwaysFails(t *testing.T) {
	for _, mode := range []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined} {
		for range 300 {
			mc := newMem(goodReplies)
			d := &socks0.Dialer{ProxyAddr: "proxy:1080", Config: &socks0.Config{Mode: mode},
				ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			c, err := d.DialContext(ctx, "tcp", "example.com:80")
			if err == nil {
				c.Close()
				t.Fatalf("%v: DialContext(canceled) succeeded", mode)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%v: %v", mode, err)
			}
			if mc.closes.Load() != 1 {
				t.Fatalf("%v: conn closed %d times", mode, mc.closes.Load())
			}
		}
	}
}

// OpError.Addr is the target as asked.
func TestVerifyBugClientConfigErrorLacksAddr(t *testing.T) {
	for name, cfg := range map[string]*socks0.Config{
		"mode":         {Mode: 9},
		"nil userpass": {Auth: (*socks0.UserPass)(nil)},
		"not pipeline": {Auth: interactive{0x80}},
		"long user":    {Auth: socks0.UserPass{Username: strings.Repeat("u", 256)}},
	} {
		c := socks0.Client(newMem(), "example.com:80", cfg)
		err := c.HandshakeContext(t.Context())
		op, ok := err.(*net.OpError)
		if !ok {
			t.Fatalf("%s: %v", name, err)
		}
		if op.Addr == nil {
			t.Errorf("%s: Client config error has no Addr: %v", name, err)
		}
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1", Config: cfg}
		_, err = d.DialContext(t.Context(), "tcp", "example.com:80")
		if op := err.(*net.OpError); op.Addr == nil {
			t.Errorf("%s: Dialer config error has no Addr", name)
		}
	}
}

func TestVerifyBugProxyDialConnAndErrorLeaks(t *testing.T) {
	mc := newMem()
	d := &socks0.Dialer{ProxyAddr: "proxy:1080",
		ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, errTest }}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); !errors.Is(err, errTest) {
		t.Fatal(err)
	}
	if mc.closes.Load() == 0 {
		t.Error("conn returned with an error by ProxyDial was not closed")
	}
}

// An opaque URL (missing "//") holds the password in Opaque, which
// u.Redacted keeps.
func TestVerifyBugParseProxyURLOpaqueLeaksPassword(t *testing.T) {
	for _, raw := range []string{
		"socks5:user:hunter2secret@proxy.example:1080",
		"http:user:hunter2secret@proxy.example:1080",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		_, err = socks0.ParseProxyURL(u)
		if err == nil {
			t.Fatalf("%s: no error", raw)
		}
		if strings.Contains(err.Error(), "hunter2secret") {
			t.Errorf("error contains the password: %v", err)
		}
		if _, err := socks0.FromURL(u); err != nil && strings.Contains(err.Error(), "hunter2secret") {
			t.Errorf("FromURL error contains the password: %v", err)
		}
	}
}

var _ = wire.StageReply

// chanConn shares no lock between Read and Close, so -race sees only
// socks0's synchronization.
type chanConn struct {
	net.Conn // nil: unused methods panic
	rd       chan []byte
}

func (c *chanConn) Read(b []byte) (int, error) {
	p, ok := <-c.rd
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(b, p), nil
}
func (c *chanConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *chanConn) Close() error                     { return nil }
func (c *chanConn) LocalAddr() net.Addr              { return memAddr("c") }
func (c *chanConn) RemoteAddr() net.Addr             { return memAddr("p") }
func (c *chanConn) SetDeadline(time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(time.Time) error { return nil }

func TestVerifyBugRaceRstageChanConn(t *testing.T) {
	cc := &chanConn{rd: make(chan []byte)}
	c := socks0.Client(cc, "example.com:80", early())
	c.Write(nil)
	rd := make(chan error)
	go func() { _, err := c.Read(make([]byte, 1)); rd <- err }()
	time.Sleep(20 * time.Millisecond)
	c.Close()
	c.HandshakeContext(t.Context())
	close(cc.rd)
	<-rd
}

// A ProxyDial returning a conn despite the canceled ctx (a pool, a mux).
func TestVerifyBugEarlyDialIgnoresCanceledCtx(t *testing.T) {
	for _, mode := range modes {
		mc := newMem(goodReplies)
		d := &socks0.Dialer{ProxyAddr: "p:1", Config: &socks0.Config{Mode: mode},
			ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c, err := d.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			c.Close()
			t.Errorf("%v: DialContext(canceled ctx) succeeded", mode)
		}
	}
}
