package socks0_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func client(t *testing.T, handle func(net.Conn), cfg *socks0.Config) (*socks0.Conn, *recConn) {
	t.Helper()
	raw, err := net.Dial("tcp", listen(t, handle))
	if err != nil {
		t.Fatal(err)
	}
	rc := &recConn{Conn: raw}
	c := socks0.Client(rc, "example.com:80", cfg)
	t.Cleanup(func() { c.Close() })
	return c, rc
}

func early(mod ...func(*socks0.Config)) *socks0.Config {
	cfg := &socks0.Config{Mode: socks0.ModeEarly}
	for _, f := range mod {
		f(cfg)
	}
	return cfg
}

var hsNoAuth = slices.Concat([]byte{5, 1, 0}, must(wire.AppendRequest(nil, wire.CmdConnect, mustAddr("example.com:80"))))

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

func TestEarlyReadBeforeWrite(t *testing.T) {
	c, rc := client(t, proxy{}.serve, early())
	got := make(chan string)
	go func() {
		b := make([]byte, 5)
		_, err := io.ReadFull(c, b)
		got <- string(b) + errString(err)
	}()
	time.Sleep(20 * time.Millisecond)
	if writes, _, _ := rc.snapshot(); len(writes) != 0 {
		t.Fatalf("wrote %q before the first Write", writes)
	}
	if n, err := c.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if s := <-got; s != "hello" {
		t.Fatalf("Read got %q", s)
	}
	if writes, _, _ := rc.snapshot(); len(writes) != 1 || !bytes.Equal(writes[0], append(hsNoAuth, "hello"...)) {
		t.Errorf("writes = %q", writes)
	}
	if c.BoundAddr() != defaultBound {
		t.Errorf("BoundAddr = %v", c.BoundAddr())
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

func TestEarlyReadWaitEnds(t *testing.T) {
	t.Run("Close", func(t *testing.T) {
		c, rc := client(t, proxy{}.serve, early())
		errc := make(chan error)
		go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
		time.Sleep(10 * time.Millisecond)
		c.Close()
		if err := <-errc; !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
			t.Errorf("Read = %v", err)
		}
		if writes, _, _ := rc.snapshot(); len(writes) != 0 {
			t.Errorf("writes = %q", writes)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		c, _ := client(t, proxy{}.serve, early())
		c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
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
		errc := make(chan error)
		go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
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
		errc := make(chan error)
		go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
		if err := c.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("x"))
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
		if writes, _, _ := rc.snapshot(); len(writes) != 2 || !bytes.Equal(writes[0], hsNoAuth) || string(writes[1]) != "x" {
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
	if writes, _, _ := rc.snapshot(); len(writes) != 1 || !bytes.Equal(writes[0], hsNoAuth) {
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
	if _, err := pc.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SyscallConn on a pipe = %v", err)
	}
	pc.Close()
}

type readerOnly struct{ io.Reader }

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
	n, err := c.ReadFrom(readerOnly{bytes.NewReader(data)})
	if n != int64(len(data)) || err != nil {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
	if got := <-done; !bytes.Equal(got, data) {
		t.Fatal("echo differs")
	}
	writes, _, _ := rc.snapshot()
	if !bytes.Equal(writes[0], append(slices.Clip(hsNoAuth), data[:32<<10]...)) {
		t.Errorf("first write is %d bytes", len(writes[0]))
	}

	// Empty source: the handshake alone. A failing source: nothing sent.
	c, rc = client(t, proxy{}.serve, early())
	if n, err := c.ReadFrom(strings.NewReader("")); n != 0 || err != nil {
		t.Errorf("ReadFrom(empty) = %d, %v", n, err)
	}
	if writes, _, _ := rc.snapshot(); len(writes) != 1 || !bytes.Equal(writes[0], hsNoAuth) {
		t.Errorf("writes = %q", writes)
	}
	c, rc = client(t, proxy{}.serve, early())
	if _, err := c.ReadFrom(iotestErrReader{}); !errors.Is(err, errTest) {
		t.Errorf("ReadFrom(failing) = %v", err)
	}
	if writes, _, _ := rc.snapshot(); len(writes) != 0 {
		t.Errorf("writes = %q", writes)
	}
	// Data and an error from one Read: sent, then the error.
	if _, err := c.ReadFrom(io.MultiReader(strings.NewReader("ab"), iotestErrReader{})); !errors.Is(err, errTest) {
		t.Errorf("ReadFrom = %v", err)
	}
	if s := readN(t, c, 2); s != "ab" {
		t.Errorf("echo %q", s)
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errTest }

func TestEarlyWriteTo(t *testing.T) {
	c, _ := client(t, proxy{tail: []byte("all the data"), after: func(net.Conn) {}}.serve, early())
	c.Write(nil) // the handshake alone
	var buf bytes.Buffer
	if n, err := c.WriteTo(&buf); n != 12 || err != nil || buf.String() != "all the data" {
		t.Errorf("WriteTo = %d, %v, %q", n, err, buf.String())
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
	calls := map[string]func() error{
		"Read":             func() error { _, err := c.Read(nil); return err },
		"Write":            func() error { _, err := c.Write(nil); return err },
		"HandshakeContext": func() error { return c.HandshakeContext(t.Context()) },
		"CloseWrite":       c.CloseWrite,
		"ReadFrom":         func() error { _, err := c.ReadFrom(strings.NewReader("x")); return err },
		"WriteTo":          func() error { _, err := c.WriteTo(io.Discard); return err },
	}
	for name, f := range calls {
		if got := f(); got != err {
			t.Errorf("%s = %v; want the sticky %v", name, got, err)
		}
	}
	if c.BoundAddr().IsValid() {
		t.Errorf("BoundAddr = %v", c.BoundAddr())
	}
}

func TestEarlyReplyTimeout(t *testing.T) {
	rt := func(d time.Duration) func(*socks0.Config) { return func(c *socks0.Config) { c.ReplyTimeout = d } }
	t.Run("expiry", func(t *testing.T) {
		c, _ := client(t, scripted(nil, true), early(rt(30*time.Millisecond)))
		c.Write([]byte("x"))
		start := time.Now()
		_, err := c.Read(make([]byte, 1))
		he := handshakeErrOf(t, err)
		if !errors.Is(err, os.ErrDeadlineExceeded) || !err.(net.Error).Timeout() || he.Stage != wire.StageMethodSelection || socks0.KindOf(err) != socks0.KindTimeout {
			t.Fatalf("Read = %v (stage %q)", err, he.Stage)
		}
		if he.Err != os.ErrDeadlineExceeded {
			t.Errorf("cause %#v", he.Err)
		}
		if d := time.Since(start); d < 25*time.Millisecond {
			t.Errorf("failed after %v", d)
		}
		if _, err2 := c.Read(nil); err2 != err {
			t.Errorf("not sticky: %v", err2)
		}
	})
	t.Run("narrows", func(t *testing.T) {
		c, _ := client(t, scripted([]byte{5, 0}, true), early(rt(time.Hour)))
		c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if err := c.HandshakeContext(t.Context()); !errors.Is(err, os.ErrDeadlineExceeded) || handshakeErrOf(t, err).Stage != wire.StageReply {
			t.Errorf("HandshakeContext = %v", err)
		}
	})
	t.Run("restores", func(t *testing.T) {
		c, _ := client(t, proxy{after: func(c net.Conn) {
			time.Sleep(100 * time.Millisecond)
			c.Write([]byte("late"))
			io.Copy(io.Discard, c)
		}}.serve, early(rt(30*time.Millisecond)))
		if err := c.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if s := readN(t, c, 4); s != "late" {
			t.Errorf("Read = %q", s)
		}
		// The caller's deadline applies again after the replies.
		c2, _ := client(t, proxy{after: func(c net.Conn) { io.Copy(io.Discard, c) }}.serve, early(rt(time.Hour)))
		c2.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		c2.Write(nil)
		if _, err := c2.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) || isHandshakeErr(err) {
			t.Errorf("Read = %v; want a plain timeout after the handshake", err)
		}
	})
	t.Run("waiters", func(t *testing.T) {
		// A Read reads the replies; HandshakeContext and WriteTo wait for it.
		c, _ := client(t, scripted(nil, true), early(rt(30*time.Millisecond)))
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
}

func TestHandshakeContextCancel(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			c, _ := client(t, scripted([]byte{5, 0}, true), &socks0.Config{Mode: mode})
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(20*time.Millisecond, cancel)
			err := c.HandshakeContext(ctx)
			if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled || handshakeErrOf(t, err).Stage != wire.StageReply {
				t.Fatalf("HandshakeContext = %v", err)
			}
			if _, err2 := c.Read(nil); err2 != err {
				t.Errorf("Read after cancel = %v; want sticky %v", err2, err)
			}
			if err2 := c.HandshakeContext(t.Context()); err2 != err {
				t.Errorf("HandshakeContext after cancel = %v", err2)
			}
		})
	}
	t.Run("waiter", func(t *testing.T) {
		// HandshakeContext waits for a Read reading the replies; its deadline fails both.
		c, _ := client(t, scripted(nil, true), early())
		c.Write(nil)
		errc := make(chan error)
		go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
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
	t.Run("canceled before", func(t *testing.T) {
		for _, mode := range modes {
			c, rc := client(t, proxy{}.serve, &socks0.Config{Mode: mode})
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := c.HandshakeContext(ctx); !errors.Is(err, context.Canceled) {
				t.Errorf("%v: HandshakeContext = %v", mode, err)
			}
			if _, err := c.Write([]byte("x")); !errors.Is(err, context.Canceled) {
				t.Errorf("%v: Write = %v", mode, err)
			}
			_ = rc
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
			c, rc := client(t, proxy{after: func(c net.Conn) {
				io.Copy(c, c)
			}}.serve, &socks0.Config{Mode: mode})
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
			writes, _, _ := rc.snapshot()
			if all := bytes.Join(writes, nil); !bytes.Equal(all, append(slices.Clip(hsNoAuth), "ping"...)) {
				t.Fatalf("%v: wrote %q", mode, all)
			}
			if err := c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
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
		calls := map[string]func() error{
			"Read":             func() error { _, err := c.Read(nil); return err },
			"Write":            func() error { _, err := c.Write(nil); return err },
			"HandshakeContext": func() error { return c.HandshakeContext(t.Context()) },
			"CloseWrite":       c.CloseWrite,
			"ReadFrom":         func() error { _, err := c.ReadFrom(strings.NewReader("x")); return err },
			"WriteTo":          func() error { _, err := c.WriteTo(io.Discard); return err },
			"Close":            c.Close,
		}
		for name, f := range calls {
			if err := f(); !errors.Is(err, net.ErrClosed) {
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
	errc := make(chan error)
	go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
	time.Sleep(10 * time.Millisecond)
	c.Close()
	if err := <-errc; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read = %v", err)
	}

	// Close during the handshake fails it with net.ErrClosed.
	for _, mode := range modes {
		c, _ := client(t, scripted(nil, true), &socks0.Config{Mode: mode})
		errc := make(chan error)
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

func TestClientConfigErrors(t *testing.T) {
	p, _ := net.Pipe()
	defer p.Close()
	for _, tt := range []struct {
		target string
		cfg    *socks0.Config
	}{
		{"example.com", nil},
		{"example.com:80", &socks0.Config{Auth: interactive{0x80}}},
		{"example.com:80", &socks0.Config{Mode: 9}},
	} {
		c := socks0.Client(p, tt.target, tt.cfg)
		err := c.HandshakeContext(t.Context())
		if he := handshakeErrOf(t, err); he.Stage != socks0.StageConfig {
			t.Errorf("%v: %v", tt, err)
		}
		if _, err2 := c.Write(nil); err2 != err {
			t.Errorf("Write = %v", err2)
		}
	}
	c := socks0.ClientAddr(p, wire.Addr{}, nil)
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
	raw, err := net.Dial("tcp", listen(t, proxy{}.serve))
	if err != nil {
		t.Fatal(err)
	}
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

type failConn struct {
	net.Conn
	n int
}

func (c *failConn) Write(b []byte) (int, error) {
	if len(b) <= c.n {
		c.n -= len(b)
		return c.Conn.Write(b)
	}
	n, _ := c.Conn.Write(b[:c.n])
	c.n = 0
	return n, errTest
}

// A failed handshake write fails at the first message not fully written.
func TestWriteStage(t *testing.T) {
	auth := socks0.UserPass{Username: "u", Password: "p"} // greeting 3, auth 5, request 18
	for _, tt := range []struct {
		n     int
		stage string
	}{
		{0, wire.StageGreeting},
		{2, wire.StageGreeting},
		{3, wire.StageUserPass},
		{7, wire.StageUserPass},
		{8, wire.StageRequest},
		{25, wire.StageRequest},
	} {
		for _, mode := range []socks0.Mode{socks0.ModePipelined, socks0.ModeEarly} {
			d := &socks0.Dialer{
				ProxyDial: func(ctx context.Context, n, a string) (net.Conn, error) {
					p, s := net.Pipe()
					go io.Copy(io.Discard, s)
					t.Cleanup(func() { s.Close() })
					return &failConn{p, tt.n}, nil
				},
				Config: &socks0.Config{Mode: mode, Auth: auth},
			}
			c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if mode == socks0.ModeEarly {
				var n int
				n, err = c.Write([]byte("data"))
				if n != 0 {
					t.Errorf("Write = %d", n)
				}
				if _, err2 := c.Read(nil); err2 != err {
					t.Errorf("Read = %v; want sticky %v", err2, err)
				}
				c.Close()
			}
			if he := handshakeErrOf(t, err); he.Stage != tt.stage || he.Err != errTest {
				t.Errorf("%v after %d bytes: %v (stage %q)", mode, tt.n, err, he.Stage)
			}
		}
	}
	// The handshake written, the data not: a plain write error.
	raw, err := net.Dial("tcp", listen(t, proxy{}.serve))
	if err != nil {
		t.Fatal(err)
	}
	c := socks0.Client(&failConn{raw, len(hsNoAuth) + 2}, "example.com:80", early())
	defer c.Close()
	if n, err := c.Write([]byte("data")); n != 2 || err != errTest {
		t.Errorf("Write = %d, %v", n, err)
	}
	if s := readN(t, c, 2); s != "da" {
		t.Errorf("Read = %q", s)
	}
}

// ModeSequential writes each message on its own: a failed write is at it.
func TestWriteStageSequential(t *testing.T) {
	auth := socks0.UserPass{Username: "u", Password: "p"}
	for _, tt := range []struct {
		n     int
		stage string
	}{{0, wire.StageGreeting}, {3, wire.StageUserPass}, {8, wire.StageRequest}} {
		d := &socks0.Dialer{
			ProxyAddr: listen(t, proxy{}.serve),
			ProxyDial: func(ctx context.Context, n, a string) (net.Conn, error) {
				c, err := new(net.Dialer).DialContext(ctx, n, a)
				return &failConn{c, tt.n}, err
			},
			Config: &socks0.Config{Mode: socks0.ModeSequential, Auth: auth},
		}
		_, err := d.DialContext(t.Context(), "tcp", "example.com:80")
		if he := handshakeErrOf(t, err); he.Stage != tt.stage || !errors.Is(err, errTest) {
			t.Errorf("after %d bytes: %v (stage %q)", tt.n, err, he.Stage)
		}
	}
}

// A failed handshake write unblocks a waiting Read; a failed reply a stuck Write.
func TestEarlyFailureUnblocks(t *testing.T) {
	raw, err := net.Dial("tcp", listen(t, scripted(nil, true)))
	if err != nil {
		t.Fatal(err)
	}
	blocked := &blockConn{Conn: raw, n: 3, release: make(chan struct{}), started: make(chan struct{})}
	c := socks0.Client(blocked, "example.com:80", early())
	defer c.Close()
	errc := make(chan error)
	go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
	go func() { _, err := c.Write([]byte("x")); errc <- err }()
	<-blocked.started
	time.Sleep(10 * time.Millisecond) // the Read reads the replies
	close(blocked.release)            // the write fails after 3 bytes
	err1, err2 := <-errc, <-errc
	if err1 != err2 || handshakeErrOf(t, err1).Stage != wire.StageRequest || !errors.Is(err1, errTest) {
		t.Errorf("errors %v, %v", err1, err2)
	}

	// The proxy refuses at once; the handshake write is stuck (pipe, nobody reads).
	p, s := net.Pipe()
	defer s.Close()
	go s.Write(append([]byte{5, 0}, reply(5, "0.0.0.0:0")...))
	c = socks0.Client(p, "example.com:80", early())
	defer c.Close()
	go func() { _, err := c.Write([]byte("x")); errc <- err }()
	_, err = c.Read(nil)
	if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyConnectionRefused {
		t.Fatalf("Read = %v", err)
	}
	if werr := <-errc; werr != err {
		t.Errorf("Write = %v", werr)
	}
}

// blockConn's first Write blocks until release, then writes n bytes and fails.
type blockConn struct {
	net.Conn
	n       int
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (c *blockConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	n, _ := c.Conn.Write(b[:c.n])
	return n, errTest
}

func TestEarlyDeadlineDuringReplies(t *testing.T) {
	c, _ := client(t, scripted(nil, true), early(func(cfg *socks0.Config) { cfg.ReplyTimeout = time.Hour }))
	c.Write(nil)
	errc := make(chan error)
	go func() { _, err := c.Read(make([]byte, 1)); errc <- err }()
	time.Sleep(10 * time.Millisecond)
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if err := <-errc; !errors.Is(err, os.ErrDeadlineExceeded) || handshakeErrOf(t, err).Stage != wire.StageMethodSelection {
		t.Errorf("Read = %v", err)
	}
}

func TestUserPassAuthenticate(t *testing.T) {
	long := strings.Repeat("x", 256)
	var buf bytes.Buffer
	if err := (socks0.UserPass{Username: long}).Authenticate(t.Context(), &buf); !errors.Is(err, wire.ErrInvalid) || buf.Len() != 0 {
		t.Errorf("long name: %v", err)
	}
	buf.Write([]byte{1, 0})
	if err := (socks0.UserPass{Username: "u", Password: "p"}).Authenticate(t.Context(), &buf); err != nil {
		t.Error(err)
	}
	if got := buf.String(); got != "\x01\x01u\x01p" {
		t.Errorf("request %q", got)
	}
	buf.Reset()
	buf.Write([]byte{1, 3})
	if err := (socks0.UserPass{}).Authenticate(t.Context(), &buf); err.Error() != "socks auth: rejected (username/password status 0x03)" {
		t.Errorf("rejection: %v", err)
	}
	if err := (socks0.UserPass{}).Authenticate(t.Context(), struct {
		io.Reader
		io.Writer
	}{strings.NewReader(""), failWriter{}}); err != errTest {
		t.Errorf("write error: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errTest }

func isHandshakeErr(err error) bool {
	_, ok := errors.AsType[*socks0.HandshakeError](err)
	return ok
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

// A ModeEarly ReadFrom that read its first data while another call claimed the handshake sends
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
		writes, _, _ := rc.snapshot()
		if all := bytes.Join(writes, nil); !bytes.Equal(all, append(slices.Clip(hsNoAuth), "ab"...)) {
			t.Errorf("wrote %q", all)
		}
	}
}
