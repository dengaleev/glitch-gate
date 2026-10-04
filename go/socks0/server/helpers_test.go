package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestMain(m *testing.M) {
	base := runtime.NumGoroutine()
	code := m.Run()
	if code == 0 {
		if err := settle(base, 10*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

// settle ignores the fuzz engine's os/signal goroutine.
func settle(base int, wait time.Duration) error {
	count := func() (int, string) {
		buf := make([]byte, 1<<20)
		all := string(buf[:runtime.Stack(buf, true)])
		n := 0
		for g := range strings.SplitSeq(all, "\n\n") {
			if !strings.Contains(g, "os/signal.") {
				n++
			}
		}
		return n, all
	}
	for end := time.Now().Add(wait); ; time.Sleep(5 * time.Millisecond) {
		n, all := count()
		if n <= base {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("goroutines: %d > baseline %d\n%s", n, base, all)
		}
	}
}

// noLeaks must be registered first: cleanups run LIFO.
func noLeaks(t *testing.T) {
	base := runtime.NumGoroutine()
	t.Cleanup(func() {
		if err := settle(base, 5*time.Second); err != nil {
			t.Error(err)
		}
	})
}

func serve(t testing.TB, s *server.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; !errors.Is(err, server.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

func open() *server.Server {
	return &server.Server{
		Handler:  &server.ConnectHandler{Filter: server.AllowAll},
		ErrorLog: quietLog,
	}
}

// echoTCP relays the FIN.
func echoTCP(t testing.TB, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
				_, _ = io.Copy(io.Discard, c)
			})
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

func echoUDP(t testing.TB, addr string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	})
	t.Cleanup(func() { pc.Close(); wg.Wait() })
	return pc.(*net.UDPConn)
}

func dial(t testing.TB, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c.(*net.TCPConn)
}

func greeting(methods ...wire.Method) []byte {
	b, err := wire.AppendGreeting(nil, methods...)
	if err != nil {
		panic(err)
	}
	return b
}

func request(cmd wire.Command, addr string) []byte {
	b, err := wire.AppendRequest(nil, cmd, mustAddr(addr))
	if err != nil {
		panic(err)
	}
	return b
}

func userPass(user, pass string) []byte {
	b, err := wire.AppendUserPass(nil, user, pass)
	if err != nil {
		panic(err)
	}
	return b
}

func mustAddr(s string) wire.Addr {
	a, err := wire.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func cat(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

func readN(t testing.TB, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read %d bytes: %v (got %x)", n, err, b)
	}
	return b
}

func expect(t testing.TB, r io.Reader, want []byte) {
	t.Helper()
	if got := readN(t, r, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func readReply(t testing.TB, r io.Reader, cmd wire.Command) (wire.Reply, wire.Addr) {
	t.Helper()
	rep, bound, err := wire.ReadReply(r, cmd)
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	return rep, bound
}

func expectEOF(t testing.TB, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if len(b) != 0 || err != nil && !isReset(err) {
		t.Fatalf("want EOF, got %x, %v", b, err)
	}
	c.Close()
}

func isReset(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "reset") || errors.Is(err, io.EOF))
}

var quietLog = log.New(io.Discard, "", 0)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newLogger(w io.Writer) *log.Logger { return log.New(w, "", 0) }

func traceAll(seen *[]string) *server.ServerTrace {
	var mu sync.Mutex
	add := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		*seen = append(*seen, fmt.Sprintf(format, args...))
	}
	return &server.ServerTrace{
		GotGreeting: func(_ context.Context, m []wire.Method) { add("greeting %v", m) },
		AuthDone:    func(_ context.Context, m wire.Method, id any, err error) { add("auth %v %v %v", m, id, err) },
		GotRequest:  func(_ context.Context, r *server.Request) { add("request %v %v", r.Command, r.Addr) },
		Replied:     func(_ context.Context, rep wire.Reply, b wire.Addr, err error) { add("replied %v %v %v", rep, b, err) },
		Dropped:     func(_ context.Context, from netip.AddrPort, err error) { add("dropped %v %v", from, err) },
		Done: func(_ context.Context, r *server.Request, st server.ConnStats, err error) {
			add("done %v %+v %v", r != nil, st, err)
		},
	}
}
