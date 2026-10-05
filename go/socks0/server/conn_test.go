package server_test

// The SOCKS5 handshake: parsing, method negotiation, deadlines, closing, ConnState and trace hooks.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// A malformed or truncated handshake ends ServeConn with a HandshakeError of its stage, after any
// reply that stage owes.
func TestMalformedHandshake(t *testing.T) {
	failure := []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, tt := range []struct {
		name  string
		msg   []byte
		fin   bool   // the client half-closes after msg
		reply []byte // all the server writes
		stage string
		kind  socks0.Kind
	}{
		{"not SOCKS", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), false, nil, wire.StageGreeting, socks0.KindProtocol},
		{"bad ATYP", cat(greeting(0), []byte{5, 1, 0, 9, 1, 2, 3, 4, 0, 80}), false, cat([]byte{5, 0}, failure), wire.StageRequest, socks0.KindProtocol},
		{"empty name", cat(greeting(0), []byte{5, 1, 0, 3, 0, 0, 80}), false, cat([]byte{5, 0}, failure), wire.StageRequest, socks0.KindProtocol},
		{"request VER", cat(greeting(0), []byte{4, 1, 0, 1, 1, 2, 3, 4, 0, 80}), false, []byte{5, 0}, wire.StageRequest, socks0.KindProtocol},
		{"EOF", nil, true, nil, wire.StageGreeting, socks0.KindEOF},
		{"EOF in greeting", []byte{5}, true, nil, wire.StageGreeting, socks0.KindEOF},
		{"EOF before request", greeting(0), true, []byte{5, 0}, wire.StageRequest, socks0.KindEOF},
		{"EOF in name", cat(greeting(0), []byte{5, 1, 0, 3, 10, 'a'}), true, []byte{5, 0}, wire.StageRequest, socks0.KindEOF},
		{"EOF in username/password", cat(greeting(2), []byte{1, 5, 'u'}), true, []byte{5, 2}, wire.StageUserPass, socks0.KindEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := open()
			s.Auth = []server.Authenticator{server.NoAuth{}, server.UserPass{}}
			c, errc := serveOne(t, s)
			_, _ = c.Write(tt.msg)
			if tt.fin {
				_ = c.CloseWrite()
			}
			expect(t, c, tt.reply)
			expectEOF(t, c)
			err := result(t, errc)
			if he := handshakeErr(t, err); he.Stage != tt.stage || socks0.KindOf(err) != tt.kind {
				t.Fatalf("%v (%s)", err, socks0.KindOf(err))
			}
			if pe, ok := errors.AsType[*wire.ProtocolError](err); tt.name == "not SOCKS" && (!ok || pe.Field != wire.FieldVER || pe.Got != 'G') {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// The server picks its first method the client offers, and no negotiation trick reaches a request
// without the selected method's auth.
func TestMethodNegotiation(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	connect := request(wire.CmdConnect, target)
	t.Run("preference", func(t *testing.T) {
		s := newServer("u", "p")
		s.Auth = append(s.Auth, server.NoAuth{})
		for _, tt := range []struct {
			offer []wire.Method
			want  wire.Method
		}{{[]wire.Method{0, 2}, 2}, {[]wire.Method{2, 0}, 2}, {[]wire.Method{0}, 0}} {
			c, errc := serveOne(t, s)
			msg := greeting(tt.offer...)
			if tt.want == 2 {
				msg = cat(msg, userPass("u", "p"))
			}
			_, _ = c.Write(cat(msg, connect, []byte("x")))
			expect(t, c, []byte{5, byte(tt.want)})
			if tt.want == 2 {
				expect(t, c, []byte{1, 0})
			}
			if rep, _ := readReply(t, c, wire.CmdConnect); rep != 0 {
				t.Fatal(rep)
			}
			expect(t, c, []byte("x"))
			_ = c.CloseWrite()
			expectEOF(t, c)
			if err := result(t, errc); err != nil {
				t.Fatal(err)
			}
		}
	})
	all := make([]wire.Method, 255)
	for i := range all {
		all[i] = wire.Method(i)
	}
	for _, tt := range []struct {
		name string
		in   []byte
		want string // hex, exactly
		err  error
	}{
		{"no acceptable method", cat(greeting(wire.MethodNoAuth, wire.MethodGSSAPI), connect), "05ff", socks0.ErrNoAcceptableMethods},
		{"offer 02, skip auth", cat(greeting(2), connect), "0502", nil},
		{"zero methods", cat([]byte{5, 0}, connect), "", nil},
		{"255 methods", cat(greeting(all...), userPass("u", "x"), connect), "05020101", socks0.ErrAuthFailed},
		{"empty user and pass", cat(greeting(2), userPass("", ""), connect), "05020101", socks0.ErrAuthFailed},
		{"NUL suffix", cat(greeting(2), userPass("u\x00", "p"), connect), "05020101", socks0.ErrAuthFailed},
		{"pass NUL suffix", cat(greeting(2), userPass("u", "p\x00"), connect), "05020101", socks0.ErrAuthFailed},
		{"auth ver 05", cat(greeting(2), []byte{5, 1, 'u', 1, 'p'}, connect), "0502", nil},
		{"duplicate greeting", cat(greeting(2), greeting(0), connect), "0502", nil},
		{"truncated userpass then EOF", cat(greeting(2), []byte{1, 5, 'u'}), "0502", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, errc := serveOne(t, newServer("u", "p"))
			_, _ = c.Write(tt.in)
			_ = c.CloseWrite()
			got, _ := io.ReadAll(c)
			if h := fmt.Sprintf("%x", got); h != tt.want {
				t.Errorf("got %s, want exactly %s", h, tt.want)
			}
			err := result(t, errc)
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("err %v, want %v", err, tt.err)
			}
			if me, ok := errors.AsType[*server.MethodError](err); tt.name == "no acceptable method" && (!ok || socks0.KindOf(err) != socks0.KindMethod ||
				len(me.Offered) != 2 || me.Error() != "socks greeting: no acceptable methods (offered no auth, GSSAPI)") {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// HandshakeTimeout is absolute: a byte every 50 ms does not extend it, and a client that never
// reads cannot pin the conn at any server write.
func TestHandshakeTimeout(t *testing.T) {
	t.Run("slow client", func(t *testing.T) {
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
	})
	for _, stage := range []string{wire.StageMethodSelection, wire.StageReply} {
		t.Run("no reader/"+stage, func(t *testing.T) {
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

// With 64 KiB of early data in flight a failing server half-closes and drains, not RSTs its
// reply; the drain is bounded.
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
	t.Run("bounded", func(t *testing.T) {
		s := withHandler(&server.ConnectHandler{})
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
	})
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
