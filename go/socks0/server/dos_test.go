package server_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// HandshakeTimeout is absolute: a byte every 50 ms does not extend it.
func TestSlowloris(t *testing.T) {
	s := open()
	s.HandshakeTimeout = 300 * time.Millisecond
	c, errc := serveOne(t, s)
	start := time.Now()
	go func() {
		for _, b := range cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")) {
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	err := result(t, errc)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cut after %v", d)
	}
	if oe, _ := errors.AsType[*net.OpError](err); oe == nil || !oe.Timeout() || socks0.KindOf(err) != socks0.KindTimeout {
		t.Fatalf("err %v", err)
	}
}

// A client that never reads cannot pin the conn at any server write.
func TestWriteDeadline(t *testing.T) {
	for _, stage := range []string{wire.StageMethodSelection, wire.StageReply} {
		t.Run(stage, func(t *testing.T) {
			cli, srv := net.Pipe() // writes block until read
			defer cli.Close()
			s := open()
			s.HandshakeTimeout = 200 * time.Millisecond
			var replyErr error
			s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
				time.Sleep(300 * time.Millisecond) // past the handshake deadline
				_, replyErr = r.Reply(0, wire.Addr{})
				return replyErr
			})
			errc := make(chan error, 1)
			go func() { errc <- s.ServeConn(context.Background(), srv) }()
			_, _ = cli.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
			if stage == wire.StageReply {
				expect(t, cli, []byte{5, 0})
			}
			err := result(t, errc)
			if stage == wire.StageReply {
				if !timedOut(replyErr) || err != replyErr {
					t.Fatalf("reply %v, ServeConn %v", replyErr, err)
				}
				return
			}
			if he, _ := errors.AsType[*socks0.HandshakeError](err); he == nil || he.Stage != stage || !he.Timeout() {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func timedOut(err error) bool {
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}

func TestMaxHandshakes(t *testing.T) {
	s := open()
	s.MaxHandshakes = 1
	target := echoTCP(t, "127.0.0.1:0")
	proxy := serve(t, s)
	idle := dial(t, proxy) // holds the only handshake slot
	time.Sleep(50 * time.Millisecond)
	over := dial(t, proxy)
	_ = over.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := over.Read(make([]byte, 1)); n != 0 || err == nil || timedOut(err) {
		t.Fatalf("over the cap: %d, %v; want closed at once", n, err)
	}
	_, _ = idle.Write(cat(greeting(0), request(wire.CmdConnect, target), []byte("x")))
	expect(t, idle, []byte{5, 0})
	readReply(t, idle, wire.CmdConnect)
	expect(t, idle, []byte("x"))
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
	expect(t, c, []byte{5, 0})
}

func TestMaxConns(t *testing.T) {
	s := open()
	s.MaxConns = 1
	target := echoTCP(t, "127.0.0.1:0")
	proxy := serve(t, s)
	a := dial(t, proxy)
	_, _ = a.Write(cat(greeting(0), request(wire.CmdConnect, target)))
	expect(t, a, []byte{5, 0})
	readReply(t, a, wire.CmdConnect)
	b := dial(t, proxy) // in the backlog, not accepted
	_, _ = b.Write(greeting(0))
	_ = b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := b.Read(make([]byte, 2)); n != 0 {
		t.Fatal("served over MaxConns")
	}
	a.Close()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, b, []byte{5, 0})
}

func TestAdmit(t *testing.T) {
	errBlocked := errors.New("blocked")
	var admitted, released atomic.Int32
	s := open()
	s.Admit = func(ctx context.Context, c net.Conn) (func(), error) {
		n := admitted.Add(1)
		release := func() { released.Add(1) }
		if n%2 == 0 {
			return release, errBlocked
		}
		return release, nil
	}
	target := echoTCP(t, "127.0.0.1:0")
	for i := range 6 {
		c, errc := serveOne(t, s)
		switch i % 3 {
		case 0: // a tunnel
			_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
		case 1: // a failed handshake
			_, _ = c.Write([]byte{9})
		}
		_ = c.CloseWrite()
		_, _ = io.ReadAll(c)
		c.Close()
		err := result(t, errc)
		if blocked := admitted.Load()%2 == 0; blocked != errors.Is(err, errBlocked) {
			t.Errorf("conn %d: %v", i, err)
		}
	}
	if admitted.Load() != 6 || released.Load() != 6 {
		t.Fatalf("admitted %d released %d", admitted.Load(), released.Load())
	}
}

// S1: with 64 KiB of early data in flight the server half-closes and drains, not RSTs the reply.
func TestLingeringClose(t *testing.T) {
	for _, tt := range []struct {
		name  string
		msg   []byte
		reply []byte
	}{
		{"denied target", cat(greeting(0), request(wire.CmdConnect, "10.0.0.1:80")), cat([]byte{5, 0}, []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})},
		{"no method", greeting(1), []byte{5, 0xFF}},
		{"auth failed", cat(greeting(2), userPass("u", "x")), []byte{5, 2, 1, 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer("u", "p")
			s.Auth = append(s.Auth, server.NoAuth{})
			s.Handler = &server.ConnectHandler{}
			c := dial(t, serve(t, s))
			go func() { _, _ = c.Write(cat(tt.msg, payload()[:64<<10])) }()
			time.Sleep(200 * time.Millisecond) // the server has replied and is closing
			got, err := io.ReadAll(c)
			if !bytes.Equal(got, tt.reply) || err != nil {
				t.Fatalf("got %x, %v; want %x then EOF", got, err, tt.reply)
			}
		})
	}
}

func TestLingerBounded(t *testing.T) {
	s := open()
	s.Handler = &server.ConnectHandler{}
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "10.0.0.1:80")))
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := c.Write(payload()[:1024]); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	start := time.Now()
	_ = result(t, errc)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("lingered %v", d)
	}
}

// B2: late calls by handlers of finished conns never see another conn's bytes.
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
