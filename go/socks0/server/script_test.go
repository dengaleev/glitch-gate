package server_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func serveOne(t testing.TB, s *server.Server) (*net.TCPConn, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		errc <- s.ServeConn(context.Background(), c)
	}()
	c := dial(t, ln.Addr().String())
	t.Cleanup(func() { c.Close(); <-done })
	return c, errc
}

func result(t testing.TB, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("ServeConn did not return")
		return nil
	}
}

func handshakeErr(t testing.TB, err error) *socks0.HandshakeError {
	t.Helper()
	oe, ok := errors.AsType[*net.OpError](err)
	if !ok || oe.Op != "socks serve" || oe.Source == nil || oe.Addr == nil {
		t.Fatalf("not a socks serve OpError: %#v", err)
	}
	if oe.Source.String() == oe.Addr.String() || !strings.HasPrefix(oe.Addr.String(), "127.0.0.1:") {
		t.Errorf("Source %v Addr %v", oe.Source, oe.Addr)
	}
	he, ok := errors.AsType[*socks0.HandshakeError](err)
	if !ok {
		t.Fatalf("no HandshakeError in %v", err)
	}
	return he
}

func TestScriptNotSOCKS(t *testing.T) {
	c, errc := serveOne(t, open())
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	expectEOF(t, c)
	err := result(t, errc)
	he := handshakeErr(t, err)
	pe, ok := errors.AsType[*wire.ProtocolError](err)
	if he.Stage != wire.StageGreeting || !ok || pe.Field != wire.FieldVER || pe.Got != 'G' || socks0.KindOf(err) != socks0.KindProtocol {
		t.Fatalf("err %v", err)
	}
}

func TestScriptV4Disabled(t *testing.T) {
	c, errc := serveOne(t, open())
	req, _ := wire.AppendRequest4(nil, wire.CmdConnect, mustAddr("192.0.2.1:80"), "")
	_, _ = c.Write(req)
	expectEOF(t, c)
	if he := handshakeErr(t, result(t, errc)); he.Stage != wire.StageGreeting {
		t.Fatal(he)
	}
}

func TestScriptNoAcceptableMethod(t *testing.T) {
	c, errc := serveOne(t, newServer("u", "p"))
	_, _ = c.Write(greeting(wire.MethodNoAuth, wire.MethodGSSAPI))
	expect(t, c, []byte{5, 0xFF})
	expectEOF(t, c)
	err := result(t, errc)
	me, ok := errors.AsType[*server.MethodError](err)
	if !ok || !errors.Is(err, socks0.ErrNoAcceptableMethods) || socks0.KindOf(err) != socks0.KindMethod ||
		len(me.Offered) != 2 || me.Error() != "socks greeting: no acceptable methods (offered no auth, GSSAPI)" {
		t.Fatalf("err %v", err)
	}
}

func TestScriptMethodPreference(t *testing.T) {
	s := newServer("u", "p")
	s.Auth = append(s.Auth, server.NoAuth{})
	target := echoTCP(t, "127.0.0.1:0")
	for _, tt := range []struct {
		offer []wire.Method
		want  wire.Method
	}{{[]wire.Method{0, 2}, 2}, {[]wire.Method{2, 0}, 2}, {[]wire.Method{0}, 0}} {
		c, errc := serveOne(t, s)
		msg := greeting(tt.offer...)
		if tt.want == 2 {
			msg = cat(msg, userPass("u", "p"))
		}
		_, _ = c.Write(cat(msg, request(wire.CmdConnect, target), []byte("x")))
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
}

func TestScriptAuthFailed(t *testing.T) {
	logs := &logBuf{}
	s := newServer("u", "secret-password")
	s.ErrorLog = newLogger(logs)
	var seen []string
	s.Trace = traceAll(&seen)
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(2), userPass("u", "wrong-password"), request(wire.CmdConnect, "192.0.2.1:80")))
	expect(t, c, []byte{5, 2, 1, 1})
	expectEOF(t, c)
	err := result(t, errc)
	he := handshakeErr(t, err)
	if he.Stage != wire.StageUserPass || !errors.Is(err, socks0.ErrAuthFailed) || socks0.KindOf(err) != socks0.KindAuth {
		t.Fatalf("err %v", err)
	}
	all := err.Error() + logs.String() + strings.Join(seen, " ")
	for _, secret := range []string{"secret-password", "wrong-password"} {
		if strings.Contains(all, secret) {
			t.Errorf("password %q leaked: %s", secret, all)
		}
	}
	// Unknown users and empty passwords fail the same way: no user oracle.
	for _, up := range [][2]string{{"nobody", "secret-password"}, {"u", ""}, {"", ""}} {
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(2), userPass(up[0], up[1])))
		expect(t, c, []byte{5, 2, 1, 1})
		if !errors.Is(result(t, errc), socks0.ErrAuthFailed) {
			t.Fatal(up)
		}
	}
}

func TestScriptCheck(t *testing.T) {
	s := open()
	errDB := errors.New("db down")
	s.Auth = []server.Authenticator{server.UserPass{Check: func(ctx context.Context, user, pass []byte) (any, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("Check ctx without the handshake deadline")
		}
		switch string(user) {
		case "ok":
			return 42, nil
		case "db":
			return nil, errDB
		}
		return nil, socks0.ErrAuthFailed
	}}}
	var ids []any
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		ids = append(ids, r.Identity)
		return errors.New("stop")
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(2), userPass("ok", "x"), request(wire.CmdConnect, "192.0.2.1:80")))
	expect(t, c, []byte{5, 2, 1, 0})
	_ = result(t, errc)
	c, errc = serveOne(t, s)
	_, _ = c.Write(cat(greeting(2), userPass("db", "x")))
	expect(t, c, []byte{5, 2, 1, 1})
	if err := result(t, errc); !errors.Is(err, errDB) || !errors.Is(err, socks0.ErrAuthFailed) {
		t.Fatalf("err %v", err)
	}
	if len(ids) != 1 || ids[0] != 42 {
		t.Fatal(ids)
	}
}

func TestScriptBadRequest(t *testing.T) {
	for _, tt := range []struct {
		name string
		req  []byte
		rep  []byte // nil: closed without a reply
	}{
		{"atyp", []byte{5, 1, 0, 9, 1, 2, 3, 4, 0, 80}, []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"empty name", []byte{5, 1, 0, 3, 0, 0, 80}, []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"ver", []byte{4, 1, 0, 1, 1, 2, 3, 4, 0, 80}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, errc := serveOne(t, open())
			_, _ = c.Write(cat(greeting(0), tt.req))
			expect(t, c, []byte{5, 0})
			expect(t, c, tt.rep)
			expectEOF(t, c)
			if he := handshakeErr(t, result(t, errc)); he.Stage != wire.StageRequest {
				t.Fatal(he)
			}
		})
	}
}

func TestScriptTruncated(t *testing.T) {
	for _, tt := range []struct {
		msg   []byte
		stage string
	}{
		{nil, wire.StageGreeting},
		{[]byte{5}, wire.StageGreeting},
		{greeting(0), wire.StageRequest},
		{cat(greeting(0), []byte{5, 1, 0, 3, 10, 'a'}), wire.StageRequest},
		{cat(greeting(2), []byte{1, 5, 'u'}), wire.StageUserPass},
	} {
		s := newServer("", "")
		s.Auth = []server.Authenticator{server.NoAuth{}, server.UserPass{}}
		c, errc := serveOne(t, s)
		_, _ = c.Write(tt.msg)
		_ = c.CloseWrite()
		err := result(t, errc)
		if he := handshakeErr(t, err); he.Stage != tt.stage || socks0.KindOf(err) != socks0.KindEOF {
			t.Errorf("%x: %v (%s)", tt.msg, err, socks0.KindOf(err))
		}
	}
}

func TestScriptUnknownCommand(t *testing.T) {
	for _, h := range []server.Handler{
		&server.Mux{Connect: &server.ConnectHandler{}},
		&server.ConnectHandler{},
		&server.AssociateHandler{},
		&server.BindHandler{},
		&server.ResolveHandler{},
	} {
		s := open()
		s.Handler = h
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), []byte{5, 0x42, 0, 1, 192, 0, 2, 1, 0, 80}))
		expect(t, c, []byte{5, 0})
		if rep, _ := readReply(t, c, 0x42); rep != wire.ReplyCommandNotSupported {
			t.Fatal(rep)
		}
		if err := result(t, errc); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("%T: %v", h, err)
		}
	}
}

func handlerReply(t *testing.T, s *server.Server, h server.HandlerFunc) (wire.Reply, error) {
	t.Helper()
	if s == nil {
		s = open()
	}
	s.Handler = h
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
	expect(t, c, []byte{5, 0})
	rep, _ := readReply(t, c, wire.CmdConnect)
	if rep != 0 {
		expectEOF(t, c)
	}
	return rep, result(t, errc)
}

// B1: the server never replies success on its own.
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
		{"panic", func(context.Context, *server.Request) error { panic("boom\n") }, 1, server.ErrNoReply},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := &logBuf{}
			s := open()
			s.ErrorLog = newLogger(logs)
			rep, err := handlerReply(t, s, tt.h)
			if rep != tt.rep || tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("rep %v err %v; want %v, %v", rep, err, tt.rep, tt.err)
			}
			if tt.name == "panic" && !strings.Contains(logs.String(), `"boom\n"`) {
				t.Errorf("panic not logged quoted: %q", logs.String())
			}
		})
	}
}

func TestPanicAfterReply(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	s := open()
	s.ErrorLog = quietLog
	s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		if _, err := r.Reply(0, wire.Addr{}); err != nil {
			return err
		}
		panic(errors.New("late"))
	})
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
	expect(t, c, []byte{5, 0})
	readReply(t, c, wire.CmdConnect)
	expectEOF(t, c)
	if err := result(t, errc); err == nil || errors.Is(err, server.ErrNoReply) || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("err %v", err)
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
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:"+strconv.Itoa(int(tt.port)))))
		expect(t, c, []byte{5, 0})
		if rep, _ := readReply(t, c, wire.CmdConnect); rep != tt.rep {
			t.Fatalf("port %d: rep %v", tt.port, rep)
		}
		if err := result(t, errc); !errors.Is(err, errPort) {
			t.Fatal(err)
		}
	}
}

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
	if _, err := req.Reply(0, wire.Addr{}); !errors.Is(err, server.ErrReplied) {
		t.Errorf("late Reply: %v", err)
	}
	if _, err := req.Peek(t.Context(), 1); !errors.Is(err, server.ErrReplied) {
		t.Errorf("late Peek: %v", err)
	}
	if b := req.Early(); b != nil {
		t.Errorf("late Early: %q", b)
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
	var zero server.Request
	if _, err := zero.Reply(0, wire.Addr{}); !errors.Is(err, server.ErrReplied) {
		t.Error(err)
	}
}

type authFunc func(context.Context, *server.AuthConn) (any, error)

func (authFunc) Method() wire.Method { return 0x80 }
func (f authFunc) Authenticate(ctx context.Context, c *server.AuthConn) (any, error) {
	return f(ctx, c)
}

func TestSOCKS4(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	req4 := func(cmd wire.Command, addr, uid string) []byte {
		b, err := wire.AppendRequest4(nil, cmd, mustAddr(addr), uid)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("no auth bypass", func(t *testing.T) {
		s := newServer("u", "p")
		s.Versions = server.V4 | server.V5
		c, errc := serveOne(t, s)
		_, _ = c.Write(req4(wire.CmdConnect, target, "u"))
		expect(t, c, []byte{0, 0x5B, 0, 0, 0, 0, 0, 0})
		expectEOF(t, c)
		if err := result(t, errc); !errors.Is(err, socks0.ErrAuthFailed) {
			t.Fatal(err)
		}
	})
	t.Run("noauth admits", func(t *testing.T) {
		s := open()
		s.Versions = server.V4
		var r4 server.Request
		s.Trace = &server.ServerTrace{GotRequest: func(_ context.Context, r *server.Request) { r4 = *r }}
		c, errc := serveOne(t, s)
		_, _ = c.Write(cat(req4(wire.CmdConnect, target, "any"), []byte("early4")))
		got := readN(t, c, 8)
		if got[0] != 0 || got[1] != 0x5A {
			t.Fatalf("reply %x", got)
		}
		expect(t, c, []byte("early4"))
		c.Close()
		_ = result(t, errc)
		if r4.Version != server.V4 || r4.Method != wire.MethodNoAuth || r4.Identity != nil || r4.Addr.String() != target {
			t.Errorf("request %+v", r4)
		}
	})
	t.Run("other command", func(t *testing.T) {
		s := open()
		s.Versions = server.V4
		c, errc := serveOne(t, s)
		_, _ = c.Write(req4(wire.CmdUDPAssociate, target, ""))
		expect(t, c, []byte{0, 0x5B, 0, 0, 0, 0, 0, 0})
		if err := result(t, errc); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatal(err)
		}
	})
	t.Run("reply mapping", func(t *testing.T) {
		for _, tt := range []struct {
			rep   wire.Reply
			bound string
			want  []byte
		}{
			{0, "1.2.3.4:5", []byte{0, 0x5A, 0, 5, 1, 2, 3, 4}},
			{0, "[2001:db8::1]:5", []byte{0, 0x5A, 0, 0, 0, 0, 0, 0}}, // S9
			{0, "example.com:5", []byte{0, 0x5A, 0, 0, 0, 0, 0, 0}},
			{5, "1.2.3.4:5", []byte{0, 0x5B, 0, 5, 1, 2, 3, 4}},
			{0x5C, "", []byte{0, 0x5C, 0, 0, 0, 0, 0, 0}},
		} {
			s := open()
			s.Versions = server.V4
			s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
				var b wire.Addr
				if tt.bound != "" {
					b = mustAddr(tt.bound)
				}
				_, err := r.Reply(tt.rep, b)
				return err
			})
			c, errc := serveOne(t, s)
			_, _ = c.Write(req4(wire.CmdConnect, "192.0.2.1:80", ""))
			expect(t, c, tt.want)
			c.Close()
			err := result(t, errc)
			if re, ok := errors.AsType[*socks0.ReplyError](err); tt.rep != 0 && (!ok || re.Version != 4 || re.Reply != tt.rep) {
				t.Errorf("err %v", err)
			}
		}
	})
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
