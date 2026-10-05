package server_test

// Authentication: username/password, custom methods over AuthConn, secrets.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// A wrong password, an unknown user and an empty password fail alike (no user oracle), with a
// table or a Check, and no password reaches an error, a trace or a log.
func TestUserPass(t *testing.T) {
	const secret = "secret-password"
	for name, a := range map[string]server.UserPass{
		"Users": {Users: map[string]string{"u": secret}},
		"Check": {Check: func(context.Context, []byte, []byte) (any, error) { return nil, errors.New("denied") }},
	} {
		t.Run(name, func(t *testing.T) {
			logs := &logBuf{}
			var seen []string
			s := open()
			s.Auth, s.ErrorLog, s.Trace = []server.Authenticator{a}, newLogger(logs), traceAll(&seen)
			for _, up := range [][2]string{{"u", "wrong-password"}, {"nobody", secret}, {"u", ""}, {"", ""}} {
				c, errc := serveOne(t, s)
				_, _ = c.Write(cat(greeting(2), userPass(up[0], up[1]), request(wire.CmdConnect, "192.0.2.1:80")))
				expect(t, c, []byte{5, 2, 1, 1})
				expectEOF(t, c)
				err := result(t, errc)
				he := handshakeErr(t, err)
				if he.Stage != wire.StageUserPass || !errors.Is(err, socks0.ErrAuthFailed) || socks0.KindOf(err) != socks0.KindAuth {
					t.Fatalf("%q: err %v", up, err)
				}
				all := fmt.Sprintf("%v %+v %#v %s %s", err, err, err, logs, strings.Join(seen, " "))
				for _, p := range []string{secret, "wrong-password"} {
					if strings.Contains(all, p) {
						t.Fatalf("password %q leaked: %s", p, all)
					}
				}
			}
		})
	}
}

func TestUserPassCheck(t *testing.T) {
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
	if err := result(t, errc); !errors.Is(err, errDB) || !errors.Is(err, socks0.ErrAuthFailed) ||
		!strings.HasSuffix(err.Error(), "status 0x01): db down") || socks0.KindOf(err) != socks0.KindAuth {
		t.Fatalf("err %v", err)
	}
	if len(ids) != 1 || ids[0] != 42 {
		t.Fatal(ids)
	}
}

// Logging the config (fmt or slog) leaks no user name or password.
func TestUserPassRedacted(t *testing.T) {
	a := server.UserPass{Users: map[string]string{"alice": "hunter2", "bob": "s3cret-pw"}}
	s := &server.Server{Auth: []server.Authenticator{a, &a, server.UserPass{Check: func(context.Context, []byte, []byte) (any, error) { return nil, nil }}}}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("start", "auth", a, "ptr", &a, "all", s.Auth)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("start", "auth", a, "ptr", &a)
	outs := map[string]string{
		"%v": fmt.Sprint(a), "%+v": fmt.Sprintf("%+v", a), "%#v": fmt.Sprintf("%#v", a), "%s": fmt.Sprintf("%s", a),
		"%q": fmt.Sprintf("%q", a), "%d": fmt.Sprintf("%d", a), "%x": fmt.Sprintf("%x", a), "ptr %+v": fmt.Sprintf("%+v", &a),
		"Auth %+v": fmt.Sprintf("%+v", s.Auth), "Auth %#v": fmt.Sprintf("%#v", s.Auth), "*Server %+v": fmt.Sprintf("%+v", s),
		"slog text": text.String(), "slog json": js.String(),
	}
	for k, v := range outs {
		for _, secret := range []string{"hunter2", "s3cret-pw", "alice", "bob", "73336372", "68756e74"} {
			if strings.Contains(v, secret) {
				t.Errorf("%s leaks %q: %s", k, secret, v)
			}
		}
	}
	if a.GoString() != a.String() || server.UserPass(s.Auth[2].(server.UserPass)).String() != "server.UserPass(Check)" {
		t.Errorf("GoString %q, with Check %q", a.GoString(), s.Auth[2])
	}
	if !strings.Contains(outs["%v"], "2 users") || !strings.Contains(outs["slog json"], `"users":2`) {
		t.Errorf("no user count: %s / %s", outs["%v"], outs["slog json"])
	}
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
	if id, err := (server.NoAuth{}).Authenticate(context.Background(), nil); id != nil || err != nil {
		t.Error("NoAuth")
	}
	var zero server.AuthConn
	if zero.LocalAddr() != nil || zero.RemoteAddr() != nil {
		t.Error("zero AuthConn addresses")
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
