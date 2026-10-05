package socks0_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestEarlyReadBeforeWrite(t *testing.T) {
	c, rc := client(t, proxy{}.serve, early())
	c.SetReadDeadline(time.Now().Add(time.Minute)) // the Read waits for the Write, not the deadline
	got := make(chan string)
	go func() {
		b := make([]byte, 5)
		_, err := io.ReadFull(c, b)
		got <- fmt.Sprint(string(b), err)
	}()
	time.Sleep(20 * time.Millisecond)
	if writes, _ := rc.snapshot(); len(writes) != 0 {
		t.Fatalf("wrote %q before the first Write", writes)
	}
	if n, err := c.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if s := <-got; s != "hello<nil>" {
		t.Fatalf("Read got %q", s)
	}
	if writes, _ := rc.snapshot(); len(writes) != 1 || !bytes.Equal(writes[0], append(hsNoAuth, "hello"...)) {
		t.Errorf("writes = %q", writes)
	}
	if c.BoundAddr() != defaultBound {
		t.Errorf("BoundAddr = %v", c.BoundAddr())
	}
}

// A Read waiting for the first Write ends on Close, its deadline, or another call's handshake.
func TestEarlyReadWaitEnds(t *testing.T) {
	t.Run("Close", func(t *testing.T) {
		c, rc := client(t, proxy{}.serve, early())
		errc := readErr(c)
		time.Sleep(10 * time.Millisecond)
		c.Close()
		if err := <-errc; !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
			t.Errorf("Read = %v", err)
		}
		if writes, _ := rc.snapshot(); len(writes) != 0 {
			t.Errorf("writes = %q", writes)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		c, _ := client(t, proxy{}.serve, early())
		c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout {
			t.Fatalf("Read = %v", err)
		}
		// Not sticky: nothing was sent.
		c.SetReadDeadline(time.Time{})
		c.Write([]byte("x"))
		if s := readN(t, c, 1); s != "x" {
			t.Errorf("Read = %q", s)
		}
	})
	t.Run("deadline set while waiting", func(t *testing.T) {
		c, _ := client(t, proxy{}.serve, early())
		errc := readErr(c)
		time.Sleep(10 * time.Millisecond)
		c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if err := <-errc; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("Read = %v", err)
		}
		c.SetDeadline(time.Unix(1, 0))
		if _, err := c.WriteTo(io.Discard); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("WriteTo = %v", err)
		}
	})
	t.Run("HandshakeContext", func(t *testing.T) {
		c, rc := client(t, proxy{}.serve, early())
		errc := readErr(c)
		if err := c.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("x"))
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
		if writes, _ := rc.snapshot(); len(writes) != 2 || !bytes.Equal(writes[0], hsNoAuth) || string(writes[1]) != "x" {
			t.Errorf("writes = %q", writes)
		}
	})
}

func TestEarlyCloseWrite(t *testing.T) {
	c, rc := client(t, proxy{after: func(c net.Conn) {
		io.Copy(io.Discard, c)
		c.Write([]byte("bye"))
	}}.serve, early())
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(c); string(b) != "bye" || err != nil {
		t.Errorf("ReadAll = %q, %v", b, err)
	}
	if writes, _ := rc.snapshot(); len(writes) != 1 || !bytes.Equal(writes[0], hsNoAuth) {
		t.Errorf("writes = %q", writes)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("Write after CloseWrite succeeded")
	}
	// net.Pipe has no CloseWrite.
	p, _ := net.Pipe()
	pc := socks0.Client(p, "example.com:80", early())
	if err := pc.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("CloseWrite on a pipe = %v", err)
	}
	pc.Close()
}

func TestEarlyReadFrom(t *testing.T) {
	data := make([]byte, 100<<10)
	rand.Read(data)
	c, rc := client(t, proxy{}.serve, early())
	done := make(chan []byte)
	go func() {
		b := make([]byte, len(data))
		io.ReadFull(c, b)
		done <- b
	}()
	n, err := c.ReadFrom(struct{ io.Reader }{bytes.NewReader(data)})
	if n != int64(len(data)) || err != nil {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
	if got := <-done; !bytes.Equal(got, data) {
		t.Fatal("echo differs")
	}
	if writes, _ := rc.snapshot(); !bytes.Equal(writes[0], append(slices.Clip(hsNoAuth), data[:32<<10]...)) {
		t.Errorf("first write is %d bytes", len(writes[0]))
	}

	// Empty source: the handshake alone. A failing source: nothing sent.
	c, rc = client(t, proxy{}.serve, early())
	if n, err := c.ReadFrom(strings.NewReader("")); n != 0 || err != nil {
		t.Errorf("ReadFrom(empty) = %d, %v", n, err)
	}
	if writes, _ := rc.snapshot(); len(writes) != 1 || !bytes.Equal(writes[0], hsNoAuth) {
		t.Errorf("writes = %q", writes)
	}
	c, rc = client(t, proxy{}.serve, early())
	if _, err := c.ReadFrom(iotest.ErrReader(errTest)); !errors.Is(err, errTest) {
		t.Errorf("ReadFrom(failing) = %v", err)
	}
	if writes, _ := rc.snapshot(); len(writes) != 0 {
		t.Errorf("writes = %q", writes)
	}
	// Data and an error from one Read: sent, then the error.
	if _, err := c.ReadFrom(io.MultiReader(strings.NewReader("ab"), iotest.ErrReader(errTest))); !errors.Is(err, errTest) {
		t.Errorf("ReadFrom = %v", err)
	}
	if s := readN(t, c, 2); s != "ab" {
		t.Errorf("echo %q", s)
	}
}

func TestEarlyWriteTo(t *testing.T) {
	c, _ := client(t, proxy{tail: []byte("all the data"), after: func(net.Conn) {}}.serve, early())
	c.Write(nil) // the handshake alone
	var buf bytes.Buffer
	if n, err := c.WriteTo(&buf); n != 12 || err != nil || buf.String() != "all the data" {
		t.Errorf("WriteTo = %d, %v, %q", n, err, buf.String())
	}
}

func TestEarlyFirstWrite(t *testing.T) {
	// The handshake carries the first 32 KiB of the first Write; the rest follows.
	mc := newMem(goodReplies)
	c := socks0.Client(mc, "example.com:80", early())
	if n, err := c.Write(make([]byte, 40<<10)); n != 40<<10 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if _, writes, _ := mc.stats(); len(writes) != 2 || len(writes[0]) != len(hsNoAuth)+32<<10 || len(writes[1]) != 8<<10 {
		t.Errorf("%d writes, the first %d bytes", len(writes), len(writes[0]))
	}

	// The server replies before reading the request; the write then fails after 2 bytes: a short Write has an error.
	mc = newMem(goodReplies)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	mc.onWrite = func(b []byte) (int, error) {
		once.Do(func() { close(started) })
		<-release
		return 2, errTest
	}
	c = socks0.Client(mc, "example.com:80", early())
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
	if r := <-wc; r.n < 4 && r.err == nil {
		t.Errorf("Write = (%d, nil): a short write without an error", r.n)
	}
}

func TestEarlySticky(t *testing.T) {
	c, _ := client(t, proxy{rep: wire.ReplyConnectionRefused}.serve, early())
	if n, err := c.Write([]byte("GET /")); n != 5 || err != nil {
		t.Fatalf("Write = %d, %v; it must not wait for the reply", n, err)
	}
	_, err := c.Read(make([]byte, 1))
	if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyConnectionRefused {
		t.Fatalf("Read = %v", err)
	}
	if he := handshakeErrOf(t, err); he.Stage != wire.StageReply {
		t.Errorf("stage %q", he.Stage)
	}
	for name, f := range connCalls(c) {
		if got := f(); got != err {
			t.Errorf("%s = %v; want the sticky %v", name, got, err)
		}
	}
	if c.BoundAddr().IsValid() {
		t.Errorf("BoundAddr = %v", c.BoundAddr())
	}
}

func TestEarlyReplyTimeout(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		for _, viaRead := range []bool{true, false} {
			c := socks0.Client(newMem(), "example.com:80", early(replyTimeout(30*time.Millisecond)))
			c.SetReadDeadline(time.Now().Add(time.Hour)) // a later deadline does not extend it
			start := time.Now()
			var err error
			if viaRead {
				c.Write([]byte("x"))
				_, err = c.Read(make([]byte, 1))
			} else {
				err = c.HandshakeContext(context.Background())
			}
			he := handshakeErrOf(t, err)
			if !errors.Is(err, os.ErrDeadlineExceeded) || !err.(net.Error).Timeout() || he.Stage != wire.StageMethodSelection || socks0.KindOf(err) != socks0.KindTimeout {
				t.Fatalf("Read = %v (stage %q)", err, he.Stage)
			}
			if he.Err != os.ErrDeadlineExceeded {
				t.Errorf("cause %#v", he.Err)
			}
			if d := time.Since(start); d < 25*time.Millisecond || d > 500*time.Millisecond {
				t.Errorf("failed after %v", d)
			}
			if _, err2 := c.Read(nil); err2 != err {
				t.Errorf("not sticky: %v", err2)
			}
		}
	})
	t.Run("an earlier deadline wins", func(t *testing.T) {
		c := socks0.Client(newMem([]byte{5, 0}), "example.com:80", early(replyTimeout(time.Hour)))
		c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if err := c.HandshakeContext(t.Context()); !errors.Is(err, os.ErrDeadlineExceeded) || handshakeErrOf(t, err).Stage != wire.StageReply {
			t.Errorf("HandshakeContext = %v", err)
		}
	})
	t.Run("deadline set during the replies", func(t *testing.T) {
		c := socks0.Client(newMem(), "example.com:80", early(replyTimeout(time.Hour)))
		c.Write(nil)
		errc := readErr(c)
		time.Sleep(10 * time.Millisecond)
		c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if err := <-errc; !errors.Is(err, os.ErrDeadlineExceeded) || handshakeErrOf(t, err).Stage != wire.StageMethodSelection {
			t.Errorf("Read = %v", err)
		}
	})
	t.Run("a deadline cleared during the wait does not extend it", func(t *testing.T) {
		c := socks0.Client(newMem(), "example.com:80", early(replyTimeout(50*time.Millisecond)))
		c.Write(nil)
		errc := readErr(c)
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
	t.Run("the caller's deadline applies again after the replies", func(t *testing.T) {
		for _, dl := range []time.Duration{0, 400 * time.Millisecond} {
			mc := newMem(goodReplies)
			c := socks0.Client(mc, "example.com:80", early(replyTimeout(30*time.Millisecond)))
			if dl > 0 {
				c.SetReadDeadline(time.Now().Add(dl))
			}
			if err := c.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			time.AfterFunc(150*time.Millisecond, func() { mc.feed([]byte("late")) })
			if s := readN(t, c, 4); s != "late" {
				t.Errorf("Read = %q (narrowed deadline leaked)", s)
			}
		}
		c := socks0.Client(newMem(goodReplies), "example.com:80", early(replyTimeout(time.Hour)))
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		c.Write(nil)
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) || isHandshakeErr(err) {
			t.Errorf("Read = %v; want a plain timeout after the handshake", err)
		}
	})
	t.Run("counted from when the replies are awaited", func(t *testing.T) {
		mc := newMem()
		c := socks0.Client(mc, "example.com:80", early(replyTimeout(80*time.Millisecond)))
		errc := readErr(c)
		time.Sleep(120 * time.Millisecond) // the Read waits for the first Write
		c.Write([]byte("x"))
		time.Sleep(20 * time.Millisecond)
		mc.feed(append(slices.Clip(goodReplies), 'y'))
		if err := <-errc; err != nil {
			t.Errorf("Read = %v", err)
		}
	})
	t.Run("waiters", func(t *testing.T) {
		// A Read reads the replies; HandshakeContext and WriteTo wait for it.
		c := socks0.Client(newMem(), "example.com:80", early(replyTimeout(30*time.Millisecond)))
		c.Write(nil)
		var wg sync.WaitGroup
		errs := make([]error, 3)
		wg.Go(func() { _, errs[0] = c.Read(make([]byte, 1)) })
		wg.Go(func() { errs[1] = c.HandshakeContext(context.Background()) })
		wg.Go(func() { _, errs[2] = c.WriteTo(io.Discard) })
		wg.Wait()
		for i, err := range errs {
			if !errors.Is(err, os.ErrDeadlineExceeded) || handshakeErrOf(t, err).Stage != wire.StageMethodSelection {
				t.Errorf("call %d: %v", i, err)
			}
		}
	})
	t.Run("CloseWrite", func(t *testing.T) {
		c, _ := client(t, scripted(nil, true), early(replyTimeout(20*time.Millisecond)))
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
	t.Run("ignored in L0 and L1", func(t *testing.T) {
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

func TestHandshakeContextCancel(t *testing.T) {
	cause := errors.New("my cause")
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			base := runtime.NumGoroutine()
			// Canceled awaiting the reply: ctx.Err(), not the cause; sticky.
			c := socks0.Client(newMem([]byte{5, 0}), "example.com:80", &socks0.Config{Mode: mode})
			ctx, cancel := context.WithCancelCause(t.Context())
			time.AfterFunc(20*time.Millisecond, func() { cancel(cause) })
			err := c.HandshakeContext(ctx)
			if !errors.Is(err, context.Canceled) || errors.Is(err, cause) || socks0.KindOf(err) != socks0.KindCanceled || handshakeErrOf(t, err).Stage != wire.StageReply {
				t.Fatalf("HandshakeContext = %v", err)
			}
			if _, err2 := c.Read(nil); err2 != err {
				t.Errorf("Read after cancel = %v; want sticky %v", err2, err)
			}
			if err2 := c.HandshakeContext(t.Context()); err2 != err {
				t.Errorf("HandshakeContext after cancel = %v", err2)
			}
			c.Close()

			// A ctx deadline: a timeout.
			c = socks0.Client(newMem([]byte{5, 0}), "example.com:80", &socks0.Config{Mode: mode})
			ctx, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
			err = c.HandshakeContext(ctx)
			cancel2()
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() || !errors.Is(err, context.DeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || handshakeErrOf(t, err).Stage != wire.StageReply {
				t.Errorf("deadline: %v", err)
			}
			c.Close()

			// Without a deadline or ctx, Close ends the handshake.
			c = socks0.Client(newMem(), "example.com:80", &socks0.Config{Mode: mode})
			errc := make(chan error, 1)
			go func() { errc <- c.HandshakeContext(context.Background()) }()
			time.Sleep(10 * time.Millisecond)
			c.Close()
			select {
			case err := <-errc:
				if !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
					t.Errorf("Close: %v kind %q", err, socks0.KindOf(err))
				}
			case <-time.After(2 * time.Second):
				t.Fatal("HandshakeContext hangs after Close")
			}

			// A conn without deadline support (some muxes) is closed, as by crypto/tls.
			mc := newMem()
			mc.ignoreDeadlines = true
			c = socks0.Client(mc, "x:1", &socks0.Config{Mode: mode})
			ctx, cancel3 := context.WithTimeout(context.Background(), 20*time.Millisecond)
			go func() { errc <- c.HandshakeContext(ctx) }()
			select {
			case <-errc:
			case <-time.After(500 * time.Millisecond):
				t.Error("HandshakeContext still blocked 480 ms after its ctx expired (conn without deadlines)")
				c.Close()
				mc.closeServer()
				<-errc
			}
			cancel3()
			waitGoroutines(t, base)
		})
	}
	t.Run("canceled before", func(t *testing.T) {
		// An instant handshake must not beat the canceled ctx.
		for _, mode := range modes {
			for i := range 300 {
				c := socks0.Client(newMem(goodReplies), "example.com:80", &socks0.Config{Mode: mode})
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := c.HandshakeContext(ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("%v: HandshakeContext = %v", mode, err)
				}
				if _, err := c.Write([]byte("x")); i == 0 && !errors.Is(err, context.Canceled) {
					t.Errorf("%v: Write = %v", mode, err)
				}
				c.Close()
			}
		}
	})
	t.Run("waiter", func(t *testing.T) {
		// HandshakeContext waits for a Read reading the replies; its deadline fails both.
		c := socks0.Client(newMem(), "example.com:80", early())
		c.Write(nil)
		errc := readErr(c)
		time.Sleep(10 * time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err := c.HandshakeContext(ctx)
		if !errors.Is(err, context.DeadlineExceeded) || !err.(net.Error).Timeout() {
			t.Errorf("HandshakeContext = %v", err)
		}
		if err2 := <-errc; err2 != err {
			t.Errorf("Read = %v", err2)
		}
	})
	t.Run("from each hook", func(t *testing.T) {
		stages := []string{"ConnectDone", "WroteHandshake", "GotMethod", "AuthDone", "GotReply"}
		for _, mode := range modes {
			for _, st := range stages {
				for _, viaDialer := range []bool{true, false} {
					if !viaDialer && st == "ConnectDone" {
						continue
					}
					name := fmt.Sprintf("%v/%s/dialer=%v", mode, st, viaDialer)
					base := runtime.NumGoroutine()
					for range 50 {
						mc := newMem(serverMsgs(true, "192.0.2.1:1"), []byte("tail"))
						ctx, cancel := context.WithCancel(context.Background())
						hook := func(s string) {
							if s == st {
								cancel()
							}
						}
						ctx = socks0.WithClientTrace(ctx, &socks0.ClientTrace{
							ConnectDone:    func(string, string, error) { hook("ConnectDone") },
							WroteHandshake: func(error) { hook("WroteHandshake") },
							GotMethod:      func(wire.Method) { hook("GotMethod") },
							AuthDone:       func(error) { hook("AuthDone") },
							GotReply:       func(wire.Reply, wire.Addr) { hook("GotReply") },
						})
						cfg := &socks0.Config{Mode: mode, Auth: upAuth}
						var c net.Conn
						var err error
						if viaDialer {
							d := &socks0.Dialer{ProxyAddr: "p:1", Config: cfg, ProxyDial: memDial(mc)}
							if c, err = d.DialContext(ctx, "tcp", "example.com:80"); err == nil {
								if sc, ok := c.(*socks0.Conn); ok {
									err = sc.HandshakeContext(ctx)
								}
							}
						} else {
							sc := socks0.Client(mc, "example.com:80", cfg)
							c, err = sc, sc.HandshakeContext(ctx)
						}
						cancel()
						if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled {
							t.Errorf("%s: %v (kind %q); a cancel during the handshake must fail it", name, err, socks0.KindOf(err))
						}
						if viaDialer && mode != socks0.ModeEarly && err != nil && mc.closes.Load() != 1 {
							t.Errorf("%s: closes = %d", name, mc.closes.Load())
						}
						if c != nil {
							c.Close()
						}
					}
					waitGoroutines(t, base)
				}
			}
		}
	})
}

// The reader must get the replies while the 8 MiB first Write is in progress.
func TestEarlyFullDuplex(t *testing.T) {
	data := make([]byte, 8<<20)
	rand.Read(data)
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			c, _ := client(t, proxy{}.serve, &socks0.Config{Mode: mode})
			var wg sync.WaitGroup
			wg.Go(func() {
				if n, err := c.Write(data); n != len(data) || err != nil {
					t.Errorf("Write = %d, %v", n, err)
				}
			})
			got := make([]byte, len(data))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, data) {
				t.Errorf("echo differs: %v", err)
			}
			wg.Wait()
		})
	}
}

func TestConnConcurrentFirstCalls(t *testing.T) {
	for _, mode := range modes {
		for range 20 {
			c, rc := client(t, proxy{}.serve, &socks0.Config{Mode: mode})
			var wg sync.WaitGroup
			wg.Go(func() {
				if _, err := c.Write([]byte("ping")); err != nil {
					t.Error(err)
				}
			})
			wg.Go(func() {
				if s := readN(t, c, 4); s != "ping" {
					t.Errorf("read %q", s)
				}
			})
			wg.Go(func() {
				if err := c.HandshakeContext(t.Context()); err != nil {
					t.Error(err)
				}
			})
			wg.Wait()
			if writes, _ := rc.snapshot(); !bytes.Equal(bytes.Join(writes, nil), append(slices.Clip(hsNoAuth), "ping"...)) {
				t.Fatalf("%v: wrote %q", mode, writes)
			}
			if err := c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// One reader, one writer, plus every any-goroutine method. Run with -race -count=50.
func TestConnHammer(t *testing.T) {
	base := runtime.NumGoroutine()
	addr := listen(t, func(c net.Conn) {
		if mrand.IntN(4) == 0 {
			time.Sleep(time.Duration(mrand.IntN(3)) * time.Millisecond)
		}
		proxy{rep: wire.Reply(mrand.IntN(2) * 5)}.serve(c)
	})
	for i := range 20 {
		raw := netDial(t, "tcp", addr)
		cfg := early()
		if i%2 == 0 {
			cfg.ReplyTimeout = time.Duration(1+mrand.IntN(5)) * time.Millisecond
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
				if _, err := c.Read(buf); err != nil {
					rec(err)
					if !errors.Is(err, os.ErrDeadlineExceeded) || mrand.IntN(3) == 0 {
						return
					}
				}
			}
		})
		wg.Go(func() { // writer
			for range 20 {
				_, err := c.Write([]byte("ping"))
				if rec(err); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
			}
		})
		for range 4 {
			wg.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(mrand.IntN(4))*time.Millisecond)
				defer cancel()
				rec(c.HandshakeContext(ctx))
			})
			wg.Go(func() {
				switch mrand.IntN(3) {
				case 0:
					rec(c.SetDeadline(time.Now().Add(time.Duration(mrand.IntN(5)) * time.Millisecond)))
				case 1:
					rec(c.SetReadDeadline(time.Time{}))
				default:
					rec(c.SetWriteDeadline(time.Now().Add(time.Millisecond)))
				}
			})
		}
		wg.Go(func() { rec(c.CloseWrite()) })
		wg.Go(func() {
			time.Sleep(time.Duration(mrand.IntN(8)) * time.Millisecond)
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
			if !isHandshakeErr(err) || errors.Is(err, net.ErrClosed) {
				continue
			}
			if sticky == nil {
				sticky = err
			} else if err != sticky {
				t.Errorf("two different handshake errors: %v / %v", sticky, err)
			}
		}
		for name, f := range connCalls(c) {
			if err := f(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("%s after Close: %v", name, err)
			}
		}
	}
	waitGoroutines(t, base+2) // listener goroutines
}

// connCalls are the calls that fail alike once a Conn failed or closed.
func connCalls(c *socks0.Conn) map[string]func() error {
	return map[string]func() error{
		"Read":             func() error { _, err := c.Read(nil); return err },
		"Write":            func() error { _, err := c.Write(nil); return err },
		"Write data":       func() error { _, err := c.Write([]byte("x")); return err },
		"HandshakeContext": func() error { return c.HandshakeContext(context.Background()) },
		"CloseWrite":       c.CloseWrite,
		"ReadFrom":         func() error { _, err := c.ReadFrom(strings.NewReader("x")); return err },
		"WriteTo":          func() error { _, err := c.WriteTo(io.Discard); return err },
	}
}

// Close racing the reply reader's stage update, over a conn without locks. Run with -race.
func TestConnCloseRacesReplyReader(t *testing.T) {
	for range 50 {
		cc := &chanConn{rd: make(chan []byte)}
		c := socks0.Client(cc, "example.com:80", early())
		c.Write(nil)
		rd := readErr(c)
		time.Sleep(2 * time.Millisecond)
		c.Close()
		c.HandshakeContext(t.Context())
		close(cc.rd)
		<-rd
	}
}

func TestConnClose(t *testing.T) {
	for _, mode := range modes {
		// net.Pipe: errors after Close do not match net.ErrClosed; writes block until read.
		p, s := net.Pipe()
		go proxy{coalesce: mode != socks0.ModeSequential}.serve(s)
		c := socks0.Client(p, "example.com:80", &socks0.Config{Mode: mode})
		if err := c.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		readN(t, c, 1)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		calls := connCalls(c)
		calls["Close"] = c.Close
		for name, f := range calls {
			if err := f(); !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
				t.Errorf("%v: %s after Close = %v", mode, name, err)
			}
		}
		if err := c.HandshakeContext(t.Context()); handshakeErrOf(t, err).Stage != wire.StageReply {
			t.Errorf("%v: HandshakeContext after Close = %v", mode, err)
		}
	}

	// Close during a data Read on a pipe: the error matches net.ErrClosed.
	p, s := net.Pipe()
	go proxy{coalesce: true, after: func(c net.Conn) { io.Copy(io.Discard, c) }}.serve(s)
	c := socks0.Client(p, "example.com:80", nil)
	if err := c.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	errc := readErr(c)
	time.Sleep(10 * time.Millisecond)
	c.Close()
	if err := <-errc; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read = %v", err)
	}

	// Close during the handshake fails it with net.ErrClosed.
	for _, mode := range modes {
		c := socks0.Client(newMem(), "example.com:80", &socks0.Config{Mode: mode})
		go func() {
			_, err := c.Write([]byte("x"))
			_, err2 := c.Read(make([]byte, 1))
			errc <- errors.Join(err, err2)
		}()
		time.Sleep(20 * time.Millisecond)
		c.Close()
		if err := <-errc; !errors.Is(err, net.ErrClosed) {
			t.Errorf("%v: %v", mode, err)
		}
	}
}

func TestConnZero(t *testing.T) {
	var zero socks0.Conn
	for name, c := range map[string]*socks0.Conn{
		"zero":      &zero,
		"nil conn":  socks0.Client(nil, "example.com:80", nil),
		"nil addr":  socks0.ClientAddr(nil, wire.Addr{}, nil),
		"nil cfg":   socks0.ClientAddr(nil, mustAddr("example.com:80"), &socks0.Config{Auth: (*socks0.UserPass)(nil)}),
		"nil auth":  socks0.Client(nil, "example.com:80", &socks0.Config{Auth: nil}),
		"nil early": socks0.Client(nil, "example.com:80", early()),
	} {
		//lint:ignore SA1012 a nil ctx must not panic either
		errs := []error{c.HandshakeContext(nil),
			c.CloseWrite(), c.Close(),
			c.SetDeadline(time.Time{}), c.SetReadDeadline(time.Time{}), c.SetWriteDeadline(time.Time{}),
		}
		_, err := c.Read(nil)
		errs = append(errs, err)
		_, err = c.Write(nil)
		errs = append(errs, err)
		_, err = c.ReadFrom(strings.NewReader("x"))
		errs = append(errs, err)
		_, err = c.WriteTo(io.Discard)
		errs = append(errs, err)
		_, err = c.SyscallConn()
		errs = append(errs, err)
		for i, err := range errs {
			if err == nil || socks0.KindOf(err) != socks0.KindConfig {
				t.Errorf("%s: call %d: %v", name, i, err)
			}
		}
		if c.LocalAddr() != nil || c.RemoteAddr() != nil || c.NetConn() != nil || c.BoundAddr().IsValid() {
			t.Errorf("%s: addresses", name)
		}
	}
}

// A config error is sticky, and its OpError.Addr is the target as asked.
func TestClientConfigErrors(t *testing.T) {
	for _, tt := range []struct {
		target string
		cfg    *socks0.Config
	}{
		{"example.com", nil},
		{"example.com:80", &socks0.Config{Auth: interactive{0x80}}},
		{"example.com:80", &socks0.Config{Mode: 9}},
		{"example.com:80", &socks0.Config{Auth: (*socks0.UserPass)(nil)}},
		{"example.com:80", &socks0.Config{Auth: socks0.UserPass{Username: strings.Repeat("u", 256)}}},
	} {
		c := socks0.Client(newMem(), tt.target, tt.cfg)
		err := c.HandshakeContext(t.Context())
		if he := handshakeErrOf(t, err); he.Stage != socks0.StageConfig {
			t.Errorf("%v: %v", tt, err)
		}
		if _, err2 := c.Write(nil); err2 != err {
			t.Errorf("Write = %v", err2)
		}
		d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1", ProxyDial: noDial(t), Config: tt.cfg}
		_, derr := d.DialContext(t.Context(), "tcp", tt.target)
		for _, err := range []error{err, derr} {
			if op := err.(*net.OpError); strings.Contains(tt.target, ":") && (op.Addr == nil || op.Addr.String() != tt.target) {
				t.Errorf("%v: OpError.Addr %v", err, op.Addr)
			}
		}
	}
	c := socks0.ClientAddr(newMem(), wire.Addr{}, nil)
	if err := c.HandshakeContext(t.Context()); !errors.Is(err, wire.ErrInvalid) {
		t.Errorf("zero Addr: %v", err)
	}
}

func TestConnAccessors(t *testing.T) {
	c, rc := client(t, proxy{}.serve, nil)
	if c.NetConn() != net.Conn(rc) || c.LocalAddr() != rc.LocalAddr() || c.RemoteAddr() != rc.RemoteAddr() {
		t.Error("accessors")
	}
	if _, err := c.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SyscallConn on a wrapper = %v", err)
	}
	raw := netDial(t, "tcp", listen(t, proxy{}.serve))
	c = socks0.Client(raw, "example.com:80", nil)
	defer c.Close()
	if sc, err := c.SyscallConn(); sc == nil || err != nil {
		t.Errorf("SyscallConn = %v, %v", sc, err)
	}
	if err := c.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Error(err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Error(err)
	}
	if err := c.HandshakeContext(t.Context()); err != nil || c.BoundAddr() != defaultBound {
		t.Errorf("HandshakeContext = %v, bound %v", err, c.BoundAddr())
	}
	if err := c.HandshakeContext(t.Context()); err != nil {
		t.Error(err)
	}
}

// A failed handshake write unblocks a Read waiting for the replies and a Write waiting for
// the handshake write; a failed reply a stuck Write.
func TestEarlyFailureUnblocks(t *testing.T) {
	mc := newMem()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	mc.onWrite = func([]byte) (int, error) {
		once.Do(func() { close(started) })
		<-release
		return 3, errTest
	}
	c := socks0.Client(mc, "example.com:80", early())
	defer c.Close()
	errc := readErr(c)
	go func() { _, err := c.Write([]byte("x")); errc <- err }()
	<-started
	go func() { _, err := c.Write([]byte("y")); errc <- err }()
	time.Sleep(10 * time.Millisecond) // the Read reads the replies
	close(release)                    // the write fails after 3 bytes
	err1, err2, err3 := <-errc, <-errc, <-errc
	if err1 != err2 || err2 != err3 || handshakeErrOf(t, err1).Stage != wire.StageRequest || !errors.Is(err1, errTest) {
		t.Errorf("errors %v, %v, %v", err1, err2, err3)
	}

	// The proxy refuses at once; the handshake write is stuck (pipe, nobody reads).
	p, s := net.Pipe()
	defer s.Close()
	go s.Write(append([]byte{5, 0}, reply(5, "0.0.0.0:0")...))
	c = socks0.Client(p, "example.com:80", early())
	defer c.Close()
	go func() { _, err := c.Write([]byte("x")); errc <- err }()
	_, err := c.Read(nil)
	if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyConnectionRefused {
		t.Fatalf("Read = %v", err)
	}
	if werr := <-errc; werr != err {
		t.Errorf("Write = %v", werr)
	}
}

// gateReader's Read closes entered, waits for release, then returns s and io.EOF.
type gateReader struct {
	s                string
	entered, release chan struct{}
}

func (r *gateReader) Read(b []byte) (int, error) {
	close(r.entered)
	<-r.release
	return copy(b, r.s), io.EOF
}

// A ReadFrom that read its first data while another call claimed the handshake sends
// the data alone, after the handshake; if the conn was closed meanwhile, it fails.
func TestEarlyReadFromLosesClaim(t *testing.T) {
	for _, closeIt := range []bool{false, true} {
		c, rc := client(t, proxy{}.serve, early())
		r := &gateReader{s: "b", entered: make(chan struct{}), release: make(chan struct{})}
		type result struct {
			n   int64
			err error
		}
		res := make(chan result, 1)
		go func() { n, err := c.ReadFrom(r); res <- result{n, err} }()
		<-r.entered
		if closeIt {
			c.Close()
		} else if n, err := c.Write([]byte("a")); n != 1 || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
		close(r.release)
		got := <-res
		if closeIt {
			if !errors.Is(got.err, net.ErrClosed) || got.n != 0 {
				t.Errorf("ReadFrom after Close = %d, %v", got.n, got.err)
			}
			continue
		}
		if got.n != 1 || got.err != nil {
			t.Fatalf("ReadFrom = %d, %v", got.n, got.err)
		}
		if s := readN(t, c, 2); s != "ab" {
			t.Errorf("echo %q", s)
		}
		if writes, _ := rc.snapshot(); !bytes.Equal(bytes.Join(writes, nil), append(slices.Clip(hsNoAuth), "ab"...)) {
			t.Errorf("wrote %q", writes)
		}
	}
}

// fastConn has ReadFrom and WriteTo, counting their use.
type fastConn struct {
	*recConn
	readFrom, writeTo atomic.Int32
}

func (c *fastConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFrom.Add(1)
	return io.Copy(struct{ io.Writer }{c.recConn}, r)
}

func (c *fastConn) WriteTo(w io.Writer) (int64, error) {
	c.writeTo.Add(1)
	return io.Copy(w, struct{ io.Reader }{c.recConn})
}

// After the handshake, io.Copy uses the underlying conn's ReadFrom and WriteTo.
func TestConnIOCopyFastPaths(t *testing.T) {
	raw, err := net.Dial("tcp", listen(t, proxy{after: func(c net.Conn) {
		io.Copy(io.Discard, c)
		c.Write([]byte("response"))
	}}.serve))
	if err != nil {
		t.Fatal(err)
	}
	fc := &fastConn{recConn: &recConn{Conn: raw}}
	c := socks0.Client(fc, "example.com:80", early())
	defer c.Close()
	src := strings.Repeat("A", 100<<10)
	if n, err := io.Copy(c, struct{ io.Reader }{strings.NewReader(src)}); err != nil || n != int64(len(src)) {
		t.Fatalf("io.Copy in = %d, %v", n, err)
	}
	if writes, _ := fc.snapshot(); fc.readFrom.Load() != 1 || len(writes[0]) != len(hsNoAuth)+32<<10 {
		t.Errorf("underlying ReadFrom used %d times; first write %d bytes, want handshake + 32 KiB", fc.readFrom.Load(), len(writes[0]))
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if n, err := io.Copy(struct{ io.Writer }{&out}, c); err != nil || out.String() != "response" || fc.writeTo.Load() != 1 {
		t.Errorf("io.Copy out = %d, %v, %q; underlying WriteTo used %d times", n, err, out.String(), fc.writeTo.Load())
	}
}
