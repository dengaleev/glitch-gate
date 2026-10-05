package server_test

// Requests and replies, and the post-reply Conn: every byte after the handshake reaches the
// handler once, by every read path, and never another conn's.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func handlerReply(t *testing.T, s *server.Server, h server.HandlerFunc) (wire.Reply, error) {
	t.Helper()
	s.Handler = h
	c, rep, _, errc := askOne(t, s, request(wire.CmdConnect, "192.0.2.1:80"))
	expectEOF(t, c)
	return rep, result(t, errc)
}

// The server never replies success on its own; a handler panic is logged quoted, and one after
// the reply is the conn's error.
func TestNeverFakeSuccess(t *testing.T) {
	errStop := errors.New("stop")
	for _, tt := range []struct {
		name string
		h    server.HandlerFunc
		rep  wire.Reply
		err  error
	}{
		{"nil without reply", func(context.Context, *server.Request) error { return nil }, 1, server.ErrNoReply},
		{"error", func(context.Context, *server.Request) error { return errStop }, 1, errStop},
		{"refused", func(context.Context, *server.Request) error { return errRefused }, repRefused, errRefused},
		{"upstream success error", func(context.Context, *server.Request) error { return &socks0.ReplyError{} }, 1, nil},
		{"upstream 04", func(context.Context, *server.Request) error {
			return &socks0.ReplyError{Reply: 4}
		}, 4, nil},
		{"replied failure", func(_ context.Context, r *server.Request) error {
			_, err := r.Reply(wire.ReplyTTLExpired, wire.Addr{})
			return err
		}, 6, nil},
		{"panic", func(context.Context, *server.Request) error { panic("bad target " + forged) }, 1, server.ErrNoReply},
		{"panic after reply", func(_ context.Context, r *server.Request) error {
			if _, err := r.Reply(0, wire.Addr{}); err != nil {
				return err
			}
			panic(errors.New("late"))
		}, 0, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := &logBuf{}
			s := open()
			s.ErrorLog = newLogger(logs)
			rep, err := handlerReply(t, s, tt.h)
			if rep != tt.rep || tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("rep %v err %v; want %v, %v", rep, err, tt.rep, tt.err)
			}
			if tt.name == "panic" && !logQuoted(logs.String()) {
				t.Errorf("panic not logged quoted: %q", logs.String())
			}
			if tt.name == "panic after reply" && (err == nil || errors.Is(err, server.ErrNoReply) || !strings.Contains(err.Error(), "panic")) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestAllow(t *testing.T) {
	errPort := errors.New("port 25 closed")
	s := open()
	s.Allow = func(_ context.Context, r *server.Request) error {
		switch r.Addr.Port() {
		case 25:
			return errors.Join(server.ErrNotAllowed, errPort)
		case 26:
			return errPort
		}
		return nil
	}
	for _, tt := range []struct {
		port uint16
		rep  wire.Reply
	}{{25, 2}, {26, 1}} {
		s.Handler = server.HandlerFunc(func(context.Context, *server.Request) error {
			t.Error("handler ran")
			return nil
		})
		_, rep, _, errc := askOne(t, s, request(wire.CmdConnect, "192.0.2.1:"+strconv.Itoa(int(tt.port))))
		if rep != tt.rep {
			t.Fatalf("port %d: rep %v", tt.port, rep)
		}
		if err := result(t, errc); !errors.Is(err, errPort) {
			t.Fatal(err)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	for _, h := range []server.Handler{
		&server.Mux{Connect: &server.ConnectHandler{}},
		&server.ConnectHandler{},
		&server.AssociateHandler{},
		&server.BindHandler{},
		&server.ResolveHandler{},
	} {
		_, rep, _, errc := askOne(t, withHandler(h), []byte{5, 0x42, 0, 1, 192, 0, 2, 1, 0, 80})
		if rep != wire.ReplyCommandNotSupported {
			t.Fatal(rep)
		}
		if err := result(t, errc); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("%T: %v", h, err)
		}
	}
}

// After the handler returns, and on the zero Request, every call fails or is empty.
func TestLateCalls(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	var req *server.Request
	var conn *server.Conn
	var ac *server.AuthConn
	s := open()
	s.Auth = []server.Authenticator{authFunc(func(_ context.Context, c *server.AuthConn) (any, error) {
		ac = c
		return nil, nil
	})}
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		req = r
		var err error
		conn, err = r.Reply(0, wire.Addr{})
		if _, err := r.Reply(0, wire.Addr{}); !errors.Is(err, server.ErrReplied) {
			t.Errorf("second Reply: %v", err)
		}
		if err := r.ReplyListening(wire.Addr{}); err == nil {
			t.Error("ReplyListening on CONNECT")
		}
		return err
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0x80), request(wire.CmdConnect, target), []byte("early, never read")))
	expect(t, c, []byte{5, 0x80})
	readReply(t, c, wire.CmdConnect)
	expectEOF(t, c)
	if err := result(t, errc); err != nil {
		t.Fatal(err)
	}
	var zero server.Request
	for _, r := range []*server.Request{req, &zero} {
		if _, err := r.Reply(0, wire.Addr{}); !errors.Is(err, server.ErrReplied) {
			t.Errorf("late Reply: %v", err)
		}
		if _, err := r.Peek(t.Context(), 1); !errors.Is(err, server.ErrReplied) {
			t.Errorf("late Peek: %v", err)
		}
		if b := r.Early(); b != nil {
			t.Errorf("late Early: %q", b)
		}
	}
	if zero.ReplyListening(wire.Addr{}) == nil {
		t.Error("ReplyListening on the zero Request")
	}
	b := make([]byte, 100)
	if n, err := conn.Read(b); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Errorf("late Read: %q, %v", b[:n], err)
	}
	var w bytes.Buffer
	if n, err := conn.WriteTo(&w); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Errorf("late WriteTo: %d, %v", n, err)
	}
	if nc, buf := conn.NetConn(); nc == nil || buf != nil || conn.Buffered() != 0 {
		t.Errorf("late NetConn: %q", buf)
	}
	if _, err := ac.ReadMessage(func(b []byte) (int, error) { return len(b), nil }); !errors.Is(err, net.ErrClosed) {
		t.Errorf("late ReadMessage: %v", err)
	}
	if _, err := ac.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("late Write: %v", err)
	}
	for range 2 {
		if err := conn.Close(); err != nil {
			t.Errorf("Close not idempotent: %v", err)
		}
	}
}

func TestRequestFields(t *testing.T) {
	var got server.Request
	var early []byte
	s := newServer("u", "p")
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		got = *r
		early = bytes.Clone(r.Early())
		return errors.New("stop")
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(2), userPass("u", "p"), request(wire.CmdUDPAssociate, "example.com:53"), []byte("tail")))
	_ = result(t, errc)
	if got.Version != server.V5 || got.Command != wire.CmdUDPAssociate || got.Addr.String() != "example.com:53" ||
		got.Method != wire.MethodUserPass || got.Identity != "u" || got.LocalAddr.String() != c.RemoteAddr().String() ||
		got.RemoteAddr.String() != c.LocalAddr().String() || string(early) != "tail" {
		t.Fatalf("%+v early %q", got, early)
	}
}

func TestVersionString(t *testing.T) {
	for v, want := range map[server.Version]string{server.V4: "socks4", server.V5: "socks5", server.V4 | server.V5: "socks4|socks5", 0: "Version(0x00)", 8: "Version(0x08)"} {
		if v.String() != want {
			t.Errorf("%d: %q", v, v.String())
		}
	}
	for st, want := range map[server.ConnState]string{server.StateNew: "new", server.StateActive: "active", server.StateTunnel: "tunnel", server.StateClosed: "closed", 9: "ConnState(9)"} {
		if st.String() != want {
			t.Errorf("%d: %q", st, st.String())
		}
	}
}

type readerOnly struct{ io.Reader }

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

// Buffered bytes, then the rest, then the FIN, by every path.
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

func TestConnAccessors(t *testing.T) {
	s := open()
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			return err
		}
		if c.LocalAddr().String() != r.LocalAddr.String() || c.RemoteAddr().String() != r.RemoteAddr.String() ||
			c.SetDeadline(time.Time{}) != nil || c.SetReadDeadline(time.Time{}) != nil || c.SetWriteDeadline(time.Time{}) != nil {
			t.Error("Conn delegation")
		}
		if n := c.Buffered(); n != 5 {
			t.Errorf("Buffered %d", n)
		}
		b := make([]byte, 2)
		_, _ = io.ReadFull(c, b)
		if n := c.Buffered(); n != 3 || string(b) != "ab" {
			t.Errorf("Buffered %d after %q", n, b)
		}
		if _, buf := c.NetConn(); string(buf) != "cde" || cap(buf) != 3 {
			t.Errorf("NetConn buffered %q cap %d", buf, cap(buf))
		}
		if _, buf := c.NetConn(); buf != nil || c.Buffered() != 0 {
			t.Error("second NetConn")
		}
		if rc, err := c.SyscallConn(); err != nil || rc == nil {
			t.Errorf("SyscallConn %v", err)
		}
		if err := c.CloseRead(); err != nil {
			t.Error(err)
		}
		return nil
	})
	_, _, _, errc := askOne(t, s, cat(request(wire.CmdConnect, "192.0.2.1:80"), []byte("abcde")))
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

// Late calls by handlers of finished conns never see another conn's bytes.
func TestNoCrossConnData(t *testing.T) {
	const conns = 300
	type kept struct {
		r *server.Request
		c *server.Conn
	}
	keep := make(chan kept, conns)
	s := open()
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		id := r.Addr.Port()
		early := bytes.Clone(r.Early()) // valid until Reply
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			return err
		}
		want := connData(id)
		var got []byte
		if id%2 == 0 {
			got, err = io.ReadAll(c)
		} else {
			var b bytes.Buffer
			_, err = c.WriteTo(&b)
			got = b.Bytes()
		}
		if err != nil || !bytes.Equal(got, want) || len(early) > 0 && !bytes.HasPrefix(want, early) {
			t.Errorf("conn %d: got %d bytes, %v", id, len(got), err)
		}
		_, _ = c.Write([]byte{1})
		keep <- kept{r, c}
		return nil
	})
	proxy := serve(t, s)

	var stale sync.WaitGroup
	stop := make(chan struct{})
	stale.Go(func() {
		var old []kept
		b := make([]byte, 4096)
		for {
			select {
			case k := <-keep:
				old = append(old, k)
			case <-stop:
				return
			}
			for _, k := range old {
				if e := k.r.Early(); e != nil {
					t.Errorf("late Early: %d bytes", len(e))
				}
				if n, _ := k.c.Read(b); n != 0 {
					t.Errorf("late Read: %d bytes", n)
				}
				if _, buf := k.c.NetConn(); buf != nil {
					t.Errorf("late NetConn: %d bytes", len(buf))
				}
				if p, _ := k.r.Peek(context.Background(), 10); p != nil {
					t.Errorf("late Peek: %d bytes", len(p))
				}
			}
		}
	})
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for id := range conns {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, fmt.Sprintf("192.0.2.1:%d", id+1)), connData(uint16(id+1))))
			_ = c.(*net.TCPConn).CloseWrite()
			if got, err := io.ReadAll(c); err != nil || len(got) != 2+10+1 {
				t.Errorf("conn %d: %x %v", id, got, err)
			}
		})
	}
	wg.Wait()
	close(stop)
	stale.Wait()
}

func connData(id uint16) []byte {
	b := make([]byte, 0, 2*(int(id)%1500+1))
	for len(b) < cap(b) {
		b = binary.BigEndian.AppendUint16(b, id)
	}
	return b
}

// An Early slice kept past Reply, against the contract, never shows another conn's bytes.
func TestStaleEarlySliceIsolated(t *testing.T) {
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
