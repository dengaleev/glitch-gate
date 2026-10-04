package socks0_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// One reader, one writer, plus every any-goroutine method. Run with -race -count=50.
func TestVerifyEarlyConnHammer(t *testing.T) {
	base := numG()
	addr := listen(t, func(c net.Conn) {
		if rand.IntN(4) == 0 {
			time.Sleep(time.Duration(rand.IntN(3)) * time.Millisecond)
		}
		proxy{rep: wire.Reply(rand.IntN(2) * 5)}.serve(c)
	})
	for i := range 20 {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		cfg := early()
		if i%2 == 0 {
			cfg.ReplyTimeout = time.Duration(1+rand.IntN(5)) * time.Millisecond
		}
		c := socks0.Client(raw, "example.com:80", cfg)
		var (
			mu   sync.Mutex
			errs []error
		)
		rec := func(err error) {
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}
		var wg sync.WaitGroup
		wg.Go(func() { // reader
			buf := make([]byte, 64)
			for {
				_, err := c.Read(buf)
				if err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						rec(err)
						return
					}
					rec(err)
					if rand.IntN(3) == 0 {
						return
					}
				}
			}
		})
		wg.Go(func() { // writer
			for range 20 {
				_, err := c.Write([]byte("ping"))
				rec(err)
				if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
			}
		})
		for range 4 {
			wg.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rand.IntN(4))*time.Millisecond)
				defer cancel()
				rec(c.HandshakeContext(ctx))
			})
			wg.Go(func() {
				switch rand.IntN(3) {
				case 0:
					rec(c.SetDeadline(time.Now().Add(time.Duration(rand.IntN(5)) * time.Millisecond)))
				case 1:
					rec(c.SetReadDeadline(time.Time{}))
				default:
					rec(c.SetWriteDeadline(time.Now().Add(time.Millisecond)))
				}
			})
		}
		wg.Go(func() { rec(c.CloseWrite()) })
		wg.Go(func() {
			time.Sleep(time.Duration(rand.IntN(8)) * time.Millisecond)
			rec(c.Close())
		})
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("hang")
		}
		c.Close()
		var sticky error
		for _, err := range errs {
			if socks0.KindOf(err) == "" {
				t.Errorf("KindOf(%v) is empty", err)
			}
			if _, ok := errors.AsType[*socks0.HandshakeError](err); !ok || errors.Is(err, net.ErrClosed) {
				continue
			}
			if sticky == nil {
				sticky = err
			} else if err != sticky {
				t.Errorf("two different handshake errors: %v / %v", sticky, err)
			}
		}
		// After Close everything matches net.ErrClosed.
		for name, f := range map[string]func() error{
			"Read":  func() error { _, err := c.Read(nil); return err },
			"Write": func() error { _, err := c.Write([]byte("x")); return err },
			"HC":    func() error { return c.HandshakeContext(context.Background()) },
			"CW":    c.CloseWrite,
		} {
			if err := f(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("%s after Close: %v", name, err)
			}
		}
	}
	checkGoroutines(t, base+2) // listener goroutines
}

// ctx canceled from each trace hook.
func TestVerifyCancelAtEveryStage(t *testing.T) {
	stages := []string{"ConnectDone", "WroteHandshake", "GotMethod", "AuthDone", "GotReply"}
	for _, mode := range modes {
		for _, st := range stages {
			for _, viaDialer := range []bool{true, false} {
				if !viaDialer && st == "ConnectDone" {
					continue
				}
				name := fmt.Sprintf("%v/%s/dialer=%v", mode, st, viaDialer)
				base := numG()
				var okCount int
				for range 50 {
					mc := newMem(serverMsgs(true, "192.0.2.1:1"), []byte("tail"))
					ctx, cancel := context.WithCancel(context.Background())
					hook := func(s string) {
						if s == st {
							cancel()
						}
					}
					tr := &socks0.ClientTrace{
						ConnectDone:    func(string, string, error) { hook("ConnectDone") },
						WroteHandshake: func(error) { hook("WroteHandshake") },
						GotMethod:      func(wire.Method) { hook("GotMethod") },
						AuthDone:       func(error) { hook("AuthDone") },
						GotReply:       func(wire.Reply, wire.Addr) { hook("GotReply") },
					}
					cfg := &socks0.Config{Mode: mode, Auth: upAuth}
					ctx = socks0.WithClientTrace(ctx, tr)
					var err error
					var c net.Conn
					if viaDialer {
						d := &socks0.Dialer{ProxyAddr: "p:1", Config: cfg,
							ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
						c, err = d.DialContext(ctx, "tcp", "example.com:80")
						if err == nil {
							if sc, ok := c.(*socks0.Conn); ok {
								err = sc.HandshakeContext(ctx)
							}
						}
					} else {
						sc := socks0.Client(mc, "example.com:80", cfg)
						c = sc
						err = sc.HandshakeContext(ctx)
					}
					cancel()
					if err == nil {
						okCount++
					} else if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled {
						t.Errorf("%s: %v (kind %q)", name, err, socks0.KindOf(err))
					}
					if viaDialer && mode != socks0.ModeEarly && err != nil && mc.closes.Load() != 1 {
						t.Errorf("%s: closes = %d", name, mc.closes.Load())
					}
					if c != nil {
						c.Close()
					}
				}
				// A cancel before the handshake completes must fail it.
				if okCount > 0 {
					t.Errorf("%s: handshake succeeded in %d/50 runs although ctx was canceled during it", name, okCount)
				}
				checkGoroutines(t, base)
			}
		}
	}
}

func TestVerifyCtxDeadline(t *testing.T) {
	for _, mode := range modes {
		base := numG()
		mc := newMem([]byte{5, 0})
		c := socks0.Client(mc, "example.com:80", &socks0.Config{Mode: mode})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := c.HandshakeContext(ctx)
		cancel()
		var ne net.Error
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() || socks0.KindOf(err) != socks0.KindTimeout {
			t.Errorf("%v: %v", mode, err)
		}
		if he := handshakeErrOf(t, err); he.Stage != wire.StageReply {
			t.Errorf("%v: stage %q", mode, he.Stage)
		}
		c.Close()
		checkGoroutines(t, base)
	}
}

func TestVerifyReplyTimeoutVsDeadlines(t *testing.T) {
	rt := func(d time.Duration) *socks0.Config { return early(func(c *socks0.Config) { c.ReplyTimeout = d }) }
	t.Run("rdl later: ReplyTimeout wins, cause is os.ErrDeadlineExceeded", func(t *testing.T) {
		mc := newMem()
		c := socks0.Client(mc, "example.com:80", rt(30*time.Millisecond))
		c.SetReadDeadline(time.Now().Add(time.Hour))
		start := time.Now()
		err := c.HandshakeContext(context.Background())
		he := handshakeErrOf(t, err)
		if he.Err != os.ErrDeadlineExceeded || time.Since(start) > 500*time.Millisecond {
			t.Errorf("%v after %v", err, time.Since(start))
		}
	})
	t.Run("rdl earlier wins", func(t *testing.T) {
		mc := newMem()
		c := socks0.Client(mc, "example.com:80", rt(time.Hour))
		c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		start := time.Now()
		err := c.HandshakeContext(context.Background())
		if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
			t.Errorf("%v after %v", err, time.Since(start))
		}
	})
	t.Run("rdl cleared during wait: still bounded", func(t *testing.T) {
		mc := newMem()
		c := socks0.Client(mc, "example.com:80", rt(50*time.Millisecond))
		c.Write(nil)
		errc := make(chan error, 1)
		go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
		time.Sleep(10 * time.Millisecond)
		c.SetReadDeadline(time.Time{})
		c.SetDeadline(time.Now().Add(time.Hour))
		select {
		case err := <-errc:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("Read = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ReplyTimeout extended by SetReadDeadline")
		}
	})
	t.Run("restored to the caller's deadline after the replies", func(t *testing.T) {
		mc := newMem(goodReplies)
		c := socks0.Client(mc, "example.com:80", rt(30*time.Millisecond))
		c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		c.Write(nil)
		time.AfterFunc(150*time.Millisecond, func() { mc.feed([]byte("late")) })
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "late" {
			t.Errorf("Read = %q, %v (narrowed deadline leaked)", b, err)
		}
		// And with no caller deadline.
		mc = newMem(goodReplies)
		c = socks0.Client(mc, "example.com:80", rt(30*time.Millisecond))
		c.Write(nil)
		time.AfterFunc(100*time.Millisecond, func() { mc.feed([]byte("late")) })
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "late" {
			t.Errorf("Read = %q, %v (narrowed deadline leaked)", b, err)
		}
	})
	t.Run("counted from when the replies are awaited", func(t *testing.T) {
		mc := newMem()
		c := socks0.Client(mc, "example.com:80", rt(80*time.Millisecond))
		errc := make(chan error, 1)
		go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
		time.Sleep(120 * time.Millisecond) // the Read waits for the first Write
		c.Write([]byte("x"))
		time.Sleep(20 * time.Millisecond)
		mc.feed(append(goodReplies, 'y'))
		if err := <-errc; err != nil {
			t.Errorf("Read = %v", err)
		}
	})
	t.Run("ignored in L0/L1", func(t *testing.T) {
		for _, mode := range modes[:2] {
			mc := newMem()
			time.AfterFunc(60*time.Millisecond, func() { mc.feed(goodReplies) })
			c := socks0.Client(mc, "example.com:80", &socks0.Config{Mode: mode, ReplyTimeout: 10 * time.Millisecond})
			if err := c.HandshakeContext(context.Background()); err != nil {
				t.Errorf("%v: %v", mode, err)
			}
		}
	})
}

func TestVerifyCloseAccounting(t *testing.T) {
	scripts := map[string][]byte{
		"ok":       goodReplies,
		"eof":      {5, 0, 5},
		"method":   {5, 0xFF},
		"reply":    append([]byte{5, 0}, reply(5, "0.0.0.0:0")...),
		"protocol": {5, 0, 5, 0, 0, 9},
		"garbage":  []byte("HTTP/1.1"),
	}
	for name, s := range scripts {
		for _, mode := range modes {
			mc := newMem(s)
			mc.closeServer()
			d := &socks0.Dialer{ProxyAddr: "p:1", Config: &socks0.Config{Mode: mode},
				ProxyDial: func(context.Context, string, string) (net.Conn, error) { return mc, nil }}
			c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
			switch {
			case mode == socks0.ModeEarly:
				if err != nil {
					t.Fatalf("%s/%v: %v", name, mode, err)
				}
				c.(*socks0.Conn).HandshakeContext(context.Background())
				if mc.closes.Load() != 0 {
					t.Errorf("%s/%v: closed before Close", name, mode)
				}
				c.Close()
				c.Close()
				if mc.closes.Load() != 1 {
					t.Errorf("%s/%v: Close closed %d times", name, mode, mc.closes.Load())
				}
			case err != nil:
				if c != nil {
					t.Errorf("%s/%v: conn and error", name, mode)
				}
				if mc.closes.Load() != 1 {
					t.Errorf("%s/%v: closes = %d", name, mode, mc.closes.Load())
				}
			default:
				if c != net.Conn(mc) || mc.closes.Load() != 0 {
					t.Errorf("%s/%v: conn %T closes %d", name, mode, c, mc.closes.Load())
				}
				c.Close()
			}
		}
	}
}

// spyConn records which fast paths are used.
type spyConn struct {
	net.Conn
	readFrom, writeTo atomic.Int32
}

func (s *spyConn) ReadFrom(r io.Reader) (int64, error) {
	s.readFrom.Add(1)
	return io.Copy(struct{ io.Writer }{s.Conn}, r)
}

func (s *spyConn) WriteTo(w io.Writer) (int64, error) {
	s.writeTo.Add(1)
	return io.Copy(w, struct{ io.Reader }{s.Conn})
}

func TestVerifyIOCopyFastPaths(t *testing.T) {
	raw, err := net.Dial("tcp", listen(t, proxy{after: func(c net.Conn) {
		io.Copy(io.Discard, c)
		c.Write([]byte("response"))
	}}.serve))
	if err != nil {
		t.Fatal(err)
	}
	spy := &spyConn{Conn: raw}
	rc := &recConnRF{spy: spy}
	c := socks0.Client(rc, "example.com:80", early())
	defer c.Close()
	src := strings.Repeat("A", 100<<10)
	n, err := io.Copy(c, struct{ io.Reader }{strings.NewReader(src)})
	if err != nil || n != int64(len(src)) {
		t.Fatalf("io.Copy in = %d, %v", n, err)
	}
	if spy.readFrom.Load() != 1 {
		t.Errorf("underlying ReadFrom used %d times", spy.readFrom.Load())
	}
	if w := rc.firstWrite(); len(w) != len(hsNoAuth)+32<<10 {
		t.Errorf("first write %d bytes; want handshake + 32 KiB", len(w))
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if n, err := io.Copy(struct{ io.Writer }{&out}, c); err != nil || out.String() != "response" {
		t.Errorf("io.Copy out = %d, %v, %q", n, err, out.String())
	}
	if spy.writeTo.Load() != 1 {
		t.Errorf("underlying WriteTo used %d times", spy.writeTo.Load())
	}
}

// recConnRF records writes and forwards ReadFrom, WriteTo and CloseWrite to the spy.
type recConnRF struct {
	spy    *spyConn
	mu     sync.Mutex
	writes [][]byte
}

func (r *recConnRF) Read(b []byte) (int, error) { return r.spy.Read(b) }
func (r *recConnRF) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.writes = append(r.writes, append([]byte(nil), b...))
	r.mu.Unlock()
	return r.spy.Write(b)
}
func (r *recConnRF) firstWrite() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writes[0]
}
func (r *recConnRF) ReadFrom(src io.Reader) (int64, error) { return r.spy.ReadFrom(src) }
func (r *recConnRF) WriteTo(w io.Writer) (int64, error)    { return r.spy.WriteTo(w) }
func (r *recConnRF) CloseWrite() error                     { return r.spy.Conn.(*net.TCPConn).CloseWrite() }
func (r *recConnRF) Close() error                          { return r.spy.Close() }
func (r *recConnRF) LocalAddr() net.Addr                   { return r.spy.LocalAddr() }
func (r *recConnRF) RemoteAddr() net.Addr                  { return r.spy.RemoteAddr() }
func (r *recConnRF) SetDeadline(t time.Time) error         { return r.spy.SetDeadline(t) }
func (r *recConnRF) SetReadDeadline(t time.Time) error     { return r.spy.SetReadDeadline(t) }
func (r *recConnRF) SetWriteDeadline(t time.Time) error    { return r.spy.SetWriteDeadline(t) }

func TestVerifyDialReturnsTCPConn(t *testing.T) {
	addr := listen(t, proxy{}.serve)
	for _, mode := range modes {
		c, err := (&socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode}}).DialContext(t.Context(), "tcp", "example.com:80")
		if err != nil {
			t.Fatal(err)
		}
		switch cc := c.(type) {
		case *net.TCPConn:
			if mode == socks0.ModeEarly {
				t.Error("L2 returned a TCPConn")
			}
		case *socks0.Conn:
			if mode != socks0.ModeEarly {
				t.Errorf("%v returned %T", mode, c)
			}
			if _, ok := cc.NetConn().(*net.TCPConn); !ok {
				t.Errorf("NetConn %T", cc.NetConn())
			}
			if _, err := cc.SyscallConn(); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("%T", c)
		}
		c.Close()
	}
}

func TestVerifyNoGoroutineLeak(t *testing.T) {
	addr := listen(t, scripted([]byte{5, 0}, true))
	base := numG()
	for i := range 60 {
		mode := modes[i%3]
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i%5)*time.Millisecond)
		d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode, ReplyTimeout: time.Millisecond}}
		c, err := d.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			if sc, ok := c.(*socks0.Conn); ok {
				sc.HandshakeContext(ctx)
			}
			c.Close()
		}
		cancel()
	}
	checkGoroutines(t, base+2) // server handlers may linger until their conns close
}
