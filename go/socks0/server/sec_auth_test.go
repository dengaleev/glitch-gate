package server_test

// Security regressions: auth and secrets. TestSec_* failed before their fix; TestSecOK_* already held.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// ipAllowNoAuth is method 00 restricted to an (empty) IP allowlist.
type ipAllowNoAuth struct{ calls *atomic.Int32 }

func (ipAllowNoAuth) Method() wire.Method { return wire.MethodNoAuth }
func (a ipAllowNoAuth) Authenticate(_ context.Context, c *server.AuthConn) (any, error) {
	a.calls.Add(1)
	return nil, fmt.Errorf("%w: %v not allowlisted", socks0.ErrAuthFailed, c.RemoteAddr())
}

func socks4Connect(ap wire.Addr) []byte {
	ip := ap.IP().As4()
	return []byte{4, 1, byte(ap.Port() >> 8), byte(ap.Port()), ip[0], ip[1], ip[2], ip[3], 0}
}

// M1: only the built-in NoAuth admits SOCKS4 without UserID, not a custom method-00 Authenticator.
func TestSec_SOCKS4NoBypassCustomMethod00(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	var calls atomic.Int32
	s := &server.Server{
		Versions: server.V4 | server.V5,
		Auth:     []server.Authenticator{ipAllowNoAuth{&calls}},
		Handler:  &server.ConnectHandler{Filter: server.AllowAll},
		ErrorLog: quietLog,
	}
	proxy := serve(t, s)

	c5 := dial(t, proxy)
	_, _ = c5.Write(cat(greeting(0), request(wire.CmdConnect, target)))
	got, _ := io.ReadAll(c5)
	if calls.Load() != 1 || len(got) > 2 {
		t.Fatalf("SOCKS5 not rejected: calls %d, got %x", calls.Load(), got)
	}

	c4 := dial(t, proxy)
	_, _ = c4.Write(append(socks4Connect(mustAddr(target)), "ping"...))
	if rep := readN(t, c4, 8); wire.Reply(rep[1]) != wire.Reply4Rejected {
		t.Fatalf("SOCKS4 with a custom method-00 authenticator: %x, want 5B", rep)
	}

	for _, a := range []server.Authenticator{server.NoAuth{}, &server.NoAuth{}} {
		s := &server.Server{Versions: server.V4 | server.V5, Auth: []server.Authenticator{a},
			Handler: &server.ConnectHandler{Filter: server.AllowAll}, ErrorLog: quietLog}
		c := dial(t, serve(t, s))
		_, _ = c.Write(append(socks4Connect(mustAddr(target)), "ping"...))
		if rep := readN(t, c, 8); wire.Reply(rep[1]) != wire.Reply4Granted {
			t.Fatalf("%T: %x", a, rep)
		}
		expect(t, c, []byte("ping"))
	}
}

func TestSecOK_SOCKS4NoBypassUserPass(t *testing.T) {
	s := &server.Server{
		Versions: server.V4 | server.V5,
		Auth:     []server.Authenticator{server.UserPass{Users: map[string]string{"u": "p"}}},
		Handler:  &server.ConnectHandler{Filter: server.AllowAll},
		ErrorLog: quietLog,
	}
	proxy := serve(t, s)
	for _, req := range [][]byte{
		{4, 1, 0, 80, 127, 0, 0, 1, 0},
		{4, 1, 0, 80, 127, 0, 0, 1, 'u', 0},
		{4, 1, 0, 80, 0, 0, 0, 1, 'u', 0, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0},
		{4, 2, 0, 80, 127, 0, 0, 1, 0},
	} {
		c := dial(t, proxy)
		_, _ = c.Write(req)
		rep := readN(t, c, 8)
		if wire.Reply(rep[1]) != wire.Reply4Rejected {
			t.Fatalf("%x: %x", req, rep)
		}
	}
}

// No negotiation trick reaches a request without the selected auth.
func TestSecOK_MethodNegotiationTricks(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	s := &server.Server{
		Auth:     []server.Authenticator{server.UserPass{Users: map[string]string{"u": "p"}}},
		Handler:  &server.ConnectHandler{Filter: server.AllowAll},
		ErrorLog: quietLog,
	}
	proxy := serve(t, s)
	all := make([]wire.Method, 255)
	for i := range all {
		all[i] = wire.Method(i)
	}
	for name, tc := range map[string]struct {
		in   []byte
		want string // hex
	}{
		"offer 02, skip auth":         {cat(greeting(2), request(wire.CmdConnect, target)), "0502"},
		"offer 00 only":               {cat(greeting(0), request(wire.CmdConnect, target)), "05ff"},
		"zero methods":                {cat([]byte{5, 0}, request(wire.CmdConnect, target)), ""},
		"255 methods":                 {cat(greeting(all...), userPass("u", "x"), request(wire.CmdConnect, target)), "05020101"},
		"empty user and pass":         {cat(greeting(2), userPass("", ""), request(wire.CmdConnect, target)), "05020101"},
		"NUL suffix":                  {cat(greeting(2), userPass("u\x00", "p"), request(wire.CmdConnect, target)), "05020101"},
		"pass NUL suffix":             {cat(greeting(2), userPass("u", "p\x00"), request(wire.CmdConnect, target)), "05020101"},
		"auth ver 05":                 {cat(greeting(2), []byte{5, 1, 'u', 1, 'p'}, request(wire.CmdConnect, target)), "0502"},
		"duplicate greeting":          {cat(greeting(2), greeting(0), request(wire.CmdConnect, target)), "0502"},
		"truncated userpass then EOF": {cat(greeting(2), []byte{1, 5, 'u'}), "0502"},
	} {
		c := dial(t, proxy)
		_, _ = c.Write(tc.in)
		_ = c.CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, _ := io.ReadAll(c)
		if h := fmt.Sprintf("%x", got); h != tc.want {
			t.Errorf("%s: got %s, want exactly %s", name, h, tc.want)
		}
	}
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(2), userPass("u", "p"), request(wire.CmdConnect, target), []byte("x")))
	expect(t, c, []byte{5, 2, 1, 0})
	if rep, _ := readReply(t, c, wire.CmdConnect); rep != 0 {
		t.Fatal(rep)
	}
}

func TestSecOK_PasswordNotInErrorsTracesLogs(t *testing.T) {
	const secret = "S3cr3t-P4ss"
	var seen []string
	var lb logBuf
	for _, a := range []server.Authenticator{
		server.UserPass{Users: map[string]string{"u": "other"}},
		server.UserPass{Check: func(_ context.Context, u, p []byte) (any, error) {
			return nil, errors.New("denied")
		}},
	} {
		s := &server.Server{Auth: []server.Authenticator{a}, Trace: traceAll(&seen), ErrorLog: newLogger(&lb)}
		cli, srv := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, cli) }()
		go func() { _, _ = cli.Write(cat(greeting(2), userPass("u", secret))); cli.Close() }()
		err := s.ServeConn(context.Background(), srv)
		for _, v := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), strings.Join(seen, "\n"), lb.String()} {
			if strings.Contains(v, secret) {
				t.Fatalf("password leaked: %s", v)
			}
		}
	}
}

// L1: logging the config (fmt or slog) leaks no user name or password.
func TestSec_ServerUserPassFmtRedacts(t *testing.T) {
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

// Log injection: a panic value carrying the client's target name.
func TestSecOK_PanicLogQuoted(t *testing.T) {
	var lb logBuf
	s := &server.Server{ErrorLog: newLogger(&lb), Handler: server.HandlerFunc(func(_ context.Context, r *server.Request) error {
		panic("bad target " + r.Addr.Name())
	})}
	cli, srv := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, cli) }()
	name := "x\n2026/10/04 00:00:00 FORGED admin login ok\r\x1b[2J"
	b := []byte{5, 1, 0, 3, byte(len(name))}
	b = append(append(b, name...), 0, 80)
	go func() { _, _ = cli.Write(cat(greeting(0), b)) }()
	_ = s.ServeConn(context.Background(), srv)
	cli.Close()
	first := strings.SplitN(lb.String(), "\n", 2)[0]
	if strings.Contains(lb.String(), "\nFORGED") || strings.Contains(lb.String(), "\x1b") || !strings.Contains(first, `\n2026/10/04`) {
		t.Fatalf("log not quoted: %q", lb.String())
	}
}

// forgingListener's first Accept error carries attacker-influenced text, then it reports closed.
type forgingListener struct {
	net.Listener
	n atomic.Int32
}

type forgedErr struct{}

func (forgedErr) Error() string {
	return "bad header \"x\"\n2026/10/04 00:00:00 FORGED admin login ok\x1b[2J"
}
func (forgedErr) Timeout() bool   { return false }
func (forgedErr) Temporary() bool { return true }

func (l *forgingListener) Accept() (net.Conn, error) {
	if l.n.Add(1) == 1 {
		return nil, forgedErr{}
	}
	return nil, net.ErrClosed
}

// INFO: accept errors are logged quoted: no log injection.
func TestSec_AcceptErrorLogQuoted(t *testing.T) {
	var lb logBuf
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server.Server{ErrorLog: newLogger(&lb)}
	if err := s.Serve(&forgingListener{Listener: ln}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve: %v", err)
	}
	out := lb.String()
	if strings.Contains(out, "\nFORGED") || strings.Contains(out, "\x1b") || !strings.Contains(out, `\n2026/10/04`) {
		t.Fatalf("accept error not quoted: %q", out)
	}
}
