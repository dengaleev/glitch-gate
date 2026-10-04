package server_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var readers = map[string]func(c *server.Conn) ([]byte, error){
	"Read": func(c *server.Conn) ([]byte, error) { return io.ReadAll(readerOnly{c}) },
	"WriteTo": func(c *server.Conn) ([]byte, error) {
		var b bytes.Buffer
		_, err := c.WriteTo(&b)
		return b.Bytes(), err
	},
	"NetConn": func(c *server.Conn) ([]byte, error) {
		nc, buf := c.NetConn()
		rest, err := io.ReadAll(nc)
		return append(bytes.Clone(buf), rest...), err
	},
	"Read1": func(c *server.Conn) ([]byte, error) { // one byte at a time
		var out []byte
		b := make([]byte, 1)
		for {
			n, err := c.Read(b)
			out = append(out, b[:n]...)
			if err == io.EOF {
				return out, nil
			}
			if err != nil {
				return out, err
			}
		}
	},
}

type readerOnly struct{ io.Reader }

// I3, I4, I6: buffered bytes, then the rest, then the FIN, by every path.
func TestConnReadPaths(t *testing.T) {
	for name, read := range readers {
		for _, size := range []int{0, 1, 100, 1500, 3000, 100 << 10} {
			t.Run(name+"/"+strconv.Itoa(size), func(t *testing.T) {
				var got []byte
				var rerr error
				stats := make(chan server.ConnStats, 1)
				s := open()
				s.Trace = &server.ServerTrace{Done: func(_ context.Context, _ *server.Request, st server.ConnStats, _ error) { stats <- st }}
				s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
					c, err := r.Reply(0, wire.Addr{})
					if err != nil {
						return err
					}
					got, rerr = read(c)
					_, _ = c.Write([]byte("bye"))
					return nil
				})
				c, errc := serveOne(t, s)
				data := payload()[:size]
				go func() {
					_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), data))
					_ = c.CloseWrite()
				}()
				expect(t, c, []byte{5, 0})
				readReply(t, c, wire.CmdConnect)
				expect(t, c, []byte("bye"))
				if err := result(t, errc); err != nil {
					t.Fatal(err)
				}
				if rerr != nil || !bytes.Equal(got, data) {
					t.Fatalf("got %d bytes, %v; want %d", len(got), rerr, size)
				}
				st := <-stats
				if want := int64(size); name != "NetConn" && st.Received != want || st.Sent != 3 {
					t.Errorf("stats %+v, want %d received", st, size)
				}
			})
		}
	}
}

func TestConnBufferedAndNetConn(t *testing.T) {
	s := open()
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			return err
		}
		if n := c.Buffered(); n != 5 {
			t.Errorf("Buffered %d", n)
		}
		b := make([]byte, 2)
		_, _ = io.ReadFull(c, b)
		if n := c.Buffered(); n != 3 || string(b) != "ab" {
			t.Errorf("Buffered %d after %q", n, b)
		}
		nc, buf := c.NetConn()
		if string(buf) != "cde" || cap(buf) != 3 {
			t.Errorf("NetConn buffered %q cap %d", buf, cap(buf))
		}
		if _, buf := c.NetConn(); buf != nil || c.Buffered() != 0 {
			t.Error("second NetConn")
		}
		rc, err := c.SyscallConn()
		if err != nil || rc == nil {
			t.Errorf("SyscallConn %v", err)
		}
		_ = nc
		return nil
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), []byte("abcde")))
	expect(t, c, []byte{5, 0})
	readReply(t, c, wire.CmdConnect)
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
}

// net.Pipe has no CloseWrite, SyscallConn, WriteTo or ReadFrom.
func TestConnWithoutOptionalMethods(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	s := open()
	done := make(chan error, 1)
	var cw, cr, sc error
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			return err
		}
		cw, cr = c.CloseWrite(), c.CloseRead()
		_, sc = c.SyscallConn()
		var b bytes.Buffer
		if _, err := c.WriteTo(&limitWriter{&b, 4}); err == nil || b.String() != "data" {
			t.Errorf("WriteTo: %q %v", b.String(), err)
		}
		if _, err := c.ReadFrom(strings.NewReader("down")); err != nil {
			t.Error(err)
		}
		return nil
	})
	go func() { done <- s.ServeConn(t.Context(), srv) }()
	go func() { _, _ = cli.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), []byte("da"))) }()
	expect(t, cli, []byte{5, 0})
	readReply(t, cli, wire.CmdConnect)
	_, _ = cli.Write([]byte("ta"))
	expect(t, cli, []byte("down"))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{cw, cr, sc} {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("want ErrUnsupported, got %v", err)
		}
	}
}

type limitWriter struct {
	w *bytes.Buffer
	n int
}

var errFull = errors.New("full")

func (l *limitWriter) Write(p []byte) (int, error) {
	m := min(len(p), l.n-l.w.Len())
	l.w.Write(p[:m])
	if l.w.Len() >= l.n {
		return m, errFull
	}
	return m, nil
}

func TestPeek(t *testing.T) {
	type peekResult struct {
		b   []byte
		err error
	}
	run := func(t *testing.T, n int, ctx func() context.Context, send func(c *net.TCPConn)) peekResult {
		var res peekResult
		s := open()
		s.HandshakeTimeout = 300 * time.Millisecond
		s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
			b, err := r.Peek(ctx(), n)
			res = peekResult{bytes.Clone(b), err}
			if early := r.Early(); !bytes.Equal(early, b) && len(early) < n {
				t.Errorf("Early %q after Peek %q", early, b)
			}
			c, err := r.Reply(0, wire.Addr{})
			if err != nil {
				return err
			}
			rest, _ := io.ReadAll(c)
			if !bytes.HasPrefix(append(bytes.Clone(b), rest...), b) {
				t.Error("Conn does not start with the peeked bytes")
			}
			return nil
		})
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), []byte("ab")))
		send(c)
		_ = result(t, errc)
		return res
	}
	bg := context.Background
	t.Run("more arrives", func(t *testing.T) {
		r := run(t, 5, bg, func(c *net.TCPConn) {
			time.Sleep(20 * time.Millisecond)
			_, _ = c.Write([]byte("cdefg"))
			_ = c.CloseWrite()
		})
		if string(r.b) != "abcde" || r.err != nil {
			t.Fatalf("%q %v", r.b, r.err)
		}
	})
	t.Run("eof", func(t *testing.T) {
		r := run(t, 5, bg, func(c *net.TCPConn) { _ = c.CloseWrite() })
		if string(r.b) != "ab" || r.err != io.EOF {
			t.Fatalf("%q %v", r.b, r.err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		r := run(t, 5, func() context.Context { return ctx }, func(c *net.TCPConn) {
			time.Sleep(100 * time.Millisecond)
			_, _ = c.Write([]byte("cd"))
			_ = c.CloseWrite()
		})
		if string(r.b) != "ab" || !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("%q %v", r.b, r.err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		r := run(t, 1<<20, bg, func(c *net.TCPConn) { _, _ = c.Write(payload()[:4096]); _ = c.CloseWrite() })
		if len(r.b) != 2<<10 || r.err != bufio.ErrBufferFull {
			t.Fatalf("%d %v", len(r.b), r.err)
		}
	})
	t.Run("handshake deadline", func(t *testing.T) {
		r := run(t, 5, bg, func(c *net.TCPConn) { time.Sleep(500 * time.Millisecond); _ = c.CloseWrite() })
		if string(r.b) != "ab" || !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Fatalf("%q %v", r.b, r.err)
		}
	})
}

// A challenge-response method via ReadMessage never consumes the pipelined request.
func TestAuthConn(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	var msgs [][]byte
	s := open()
	s.Auth = []server.Authenticator{authFunc(func(ctx context.Context, c *server.AuthConn) (any, error) {
		if c.LocalAddr() == nil || c.RemoteAddr() == nil {
			t.Error("addresses")
		}
		_, _ = c.Write([]byte("challenge"))
		for range 2 {
			m, err := c.ReadMessage(func(b []byte) (int, error) { // length-prefixed
				if len(b) < 1 || len(b) < 1+int(b[0]) {
					return 1 + int(append(b, 0)[0]), wire.ErrIncomplete
				}
				return 1 + int(b[0]), nil
			})
			if err != nil {
				return nil, err
			}
			msgs = append(msgs, bytes.Clone(m))
		}
		_, _ = c.Write([]byte("ok"))
		return "custom", nil
	})}
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0x80), []byte{3, 'a', 'b', 'c'}, []byte{0}, request(wire.CmdConnect, target), []byte("x")))
	expect(t, c, []byte("\x05\x80challengeok"))
	readReply(t, c, wire.CmdConnect)
	expect(t, c, []byte("x"))
	c.Close()
	_ = result(t, errc)
	if len(msgs) != 2 || string(msgs[0]) != "\x03abc" || string(msgs[1]) != "\x00" {
		t.Fatalf("%q", msgs)
	}
}

func TestAuthConnErrors(t *testing.T) {
	errCustom := errors.New("custom failure")
	for _, tt := range []struct {
		name  string
		auth  func(context.Context, *server.AuthConn) (any, error)
		reply []byte // after the selection
		err   error
	}{
		{"too long", func(_ context.Context, c *server.AuthConn) (any, error) {
			return c.ReadMessage(func(b []byte) (int, error) { return 2000, wire.ErrIncomplete })
		}, nil, nil},
		{"contract", func(_ context.Context, c *server.AuthConn) (any, error) {
			return c.ReadMessage(func(b []byte) (int, error) { return len(b) + 1, nil })
		}, nil, nil},
		{"not a rejection: status dropped", func(_ context.Context, c *server.AuthConn) (any, error) {
			_, _ = c.Write([]byte{1, 1})
			return nil, errCustom
		}, nil, errCustom},
		{"rejection: status sent", func(_ context.Context, c *server.AuthConn) (any, error) {
			_, _ = c.Write([]byte{1, 1})
			return nil, errors.Join(socks0.ErrAuthFailed, errCustom)
		}, []byte{1, 1}, socks0.ErrAuthFailed},
		{"big write", func(_ context.Context, c *server.AuthConn) (any, error) {
			_, _ = c.Write(make([]byte, 600))
			_, _ = c.Write(make([]byte, 600))
			_, _ = c.Write(make([]byte, 2000))
			return nil, socks0.ErrAuthFailed
		}, make([]byte, 3200), socks0.ErrAuthFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := open()
			s.Auth = []server.Authenticator{authFunc(tt.auth)}
			c, errc := serveOne(t, s)
			_, _ = c.Write(cat(greeting(0x80), []byte{1, 2, 3}))
			expect(t, c, []byte{5, 0x80})
			expect(t, c, tt.reply)
			expectEOF(t, c)
			err := result(t, errc)
			if he := handshakeErr(t, err); he.Stage != socks0.StageAuth || tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestCredentialsZeroed(t *testing.T) {
	var msg []byte
	s := open()
	s.Auth = []server.Authenticator{authFunc(func(ctx context.Context, c *server.AuthConn) (any, error) {
		m, err := c.ReadMessage(func(b []byte) (int, error) {
			_, _, n, err := wire.ParseUserPass(b)
			return n, err
		})
		msg = m // retained past its validity on purpose
		return nil, err
	})}
	s.Handler = server.HandlerFunc(func(context.Context, *server.Request) error {
		if !bytes.Equal(msg, make([]byte, len(msg))) {
			t.Errorf("credentials not zeroed: %q", msg)
		}
		return nil
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0x80), userPass("user", "hunter2"), request(wire.CmdConnect, "192.0.2.1:80")))
	expect(t, c, []byte{5, 0x80})
	_ = result(t, errc)
}

func TestConnStateAndTrace(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	var mu sync.Mutex
	var states []server.ConnState
	var seen []string
	s := newServer("u", "p")
	s.ConnState = func(_ net.Conn, st server.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		states = append(states, st)
	}
	s.Trace = traceAll(&seen)
	c := dial(t, serve(t, s))
	_, _ = c.Write(cat(greeting(2), userPass("u", "p"), request(wire.CmdConnect, target), []byte("hi")))
	expect(t, c, []byte{5, 2, 1, 0})
	readReply(t, c, wire.CmdConnect)
	expect(t, c, []byte("hi"))
	_ = c.CloseWrite()
	expectEOF(t, c)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(states) == 4 })
	if want := []server.ConnState{server.StateNew, server.StateActive, server.StateTunnel, server.StateClosed}; !slices.Equal(states, want) {
		t.Errorf("states %v", states)
	}
	want := []string{"greeting [username/password]", "auth username/password u <nil>", "request CONNECT " + target, "replied succeeded", "done true {Received:2 Sent:2} <nil>"}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) == len(want) })
	for i, w := range want {
		if !strings.HasPrefix(seen[i], w) {
			t.Errorf("hook %d: %q, want %q…", i, seen[i], w)
		}
	}

	states = nil
	c = dial(t, serve(t, s))
	_, _ = c.Write([]byte{9})
	expectEOF(t, c)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(states) == 2 })
	if !slices.Equal(states, []server.ConnState{server.StateNew, server.StateClosed}) {
		t.Errorf("states %v", states)
	}
}

func waitFor(t testing.TB, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("timed out waiting")
		}
	}
}
