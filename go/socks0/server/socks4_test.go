package server_test

// SOCKS4 and 4a: admission (only the built-in NoAuth or UserID admits; no auth bypass), commands,
// reply mapping.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"

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

func TestSOCKS4(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	var calls atomic.Int32
	custom := ipAllowNoAuth{&calls}
	up := server.UserPass{Users: map[string]string{"u": "p"}}
	both := server.V4 | server.V5
	rejected := []byte{0, 0x5B, 0, 0, 0, 0, 0, 0}
	t.Run("custom method 00 rejects SOCKS5", func(t *testing.T) {
		s := open()
		s.Auth = []server.Authenticator{custom}
		c := dial(t, serve(t, s))
		_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
		if got, _ := io.ReadAll(c); calls.Load() != 1 || len(got) > 2 {
			t.Fatalf("SOCKS5 not rejected: calls %d, got %x", calls.Load(), got)
		}
	})
	for _, tt := range []struct {
		name     string
		versions server.Version
		auth     []server.Authenticator // nil: the default
		h        server.Handler         // nil: CONNECT
		req      []byte
		reply    []byte // nil: closed without a reply; a grant echoes "early"
		err      error
	}{
		{"disabled", server.V5, nil, nil, request4(wire.CmdConnect, "192.0.2.1:80", ""), nil, nil},
		{"default admits", server.V4, nil, nil, request4(wire.CmdConnect, target, "any"), []byte{0, 0x5A}, nil},
		{"NoAuth admits", both, []server.Authenticator{server.NoAuth{}}, nil, request4(wire.CmdConnect, target, ""), []byte{0, 0x5A}, nil},
		{"*NoAuth admits", both, []server.Authenticator{&server.NoAuth{}}, nil, request4(wire.CmdConnect, target, ""), []byte{0, 0x5A}, nil},
		{"custom method 00", both, []server.Authenticator{custom}, nil, request4(wire.CmdConnect, target, ""), rejected, nil},
		{"UserPass: USERID", both, []server.Authenticator{up}, nil, request4(wire.CmdConnect, target, "u"), rejected, socks0.ErrAuthFailed},
		{"UserPass: no USERID", both, []server.Authenticator{up}, nil, []byte{4, 1, 0, 80, 127, 0, 0, 1, 0}, rejected, nil},
		{"UserPass: SOCKS4a", both, []server.Authenticator{up}, nil, []byte{4, 1, 0, 80, 0, 0, 0, 1, 'u', 0, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0}, rejected, nil},
		{"UserPass: BIND", both, []server.Authenticator{up}, nil, []byte{4, 2, 0, 80, 127, 0, 0, 1, 0}, rejected, nil},
		{"other command", server.V4, nil, nil, request4(wire.CmdUDPAssociate, target, ""), rejected, errors.ErrUnsupported},
		{"RESOLVE handler", server.V4, nil, &server.ResolveHandler{}, request4(wire.CmdConnect, "1.2.3.4:80", ""), rejected, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := open()
			s.Versions, s.Auth = tt.versions, tt.auth
			if tt.h != nil {
				s.Handler = tt.h
			}
			var r4 server.Request
			s.Trace = &server.ServerTrace{GotRequest: func(_ context.Context, r *server.Request) { r4 = *r }}
			c, errc := serveOne(t, s)
			_, _ = c.Write(cat(tt.req, []byte("early")))
			switch {
			case tt.reply == nil:
				expectEOF(t, c)
				if he := handshakeErr(t, result(t, errc)); he.Stage != wire.StageGreeting {
					t.Fatal(he)
				}
				return
			case tt.reply[1] == 0x5A:
				if got := readN(t, c, 8); got[0] != 0 || got[1] != 0x5A {
					t.Fatalf("reply %x", got)
				}
				expect(t, c, []byte("early"))
				c.Close()
				if r4.Version != server.V4 || r4.Method != wire.MethodNoAuth || r4.Identity != nil || r4.Addr.String() != target {
					t.Errorf("request %+v", r4)
				}
			default:
				expect(t, c, tt.reply)
				expectEOF(t, c)
			}
			if err := result(t, errc); tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatal(err)
			}
		})
	}
	t.Run("reply mapping", func(t *testing.T) {
		for _, tt := range []struct {
			rep   wire.Reply
			bound string
			want  []byte
		}{
			{0, "1.2.3.4:5", []byte{0, 0x5A, 0, 5, 1, 2, 3, 4}},
			{0, "[2001:db8::1]:5", []byte{0, 0x5A, 0, 0, 0, 0, 0, 0}},
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
			_, _ = c.Write(request4(wire.CmdConnect, "192.0.2.1:80", ""))
			expect(t, c, tt.want)
			c.Close()
			err := result(t, errc)
			if re, ok := errors.AsType[*socks0.ReplyError](err); tt.rep != 0 && (!ok || re.Version != 4 || re.Reply != tt.rep) {
				t.Errorf("err %v", err)
			}
		}
	})
}

func TestInteropSOCKS4(t *testing.T) {
	s := open()
	s.Versions = server.V4 | server.V5
	s.Auth = []server.Authenticator{server.UserPass{Users: map[string]string{"u": "p"}}}
	var ids []any
	s.UserID = func(_ context.Context, uid []byte) (any, error) {
		if string(uid) != "alice" {
			return nil, errors.New("unknown user id")
		}
		return "alice", nil
	}
	s.Trace = &server.ServerTrace{GotRequest: func(_ context.Context, r *server.Request) { ids = append(ids, r.Identity, r.Method) }}
	s.Handler = &server.Mux{Connect: &server.ConnectHandler{Filter: server.AllowAll}, Bind: &server.BindHandler{Filter: server.AllowAll}}
	proxy := serve(t, s)
	named := echoLocalhost(t) // SOCKS4a resolves at the server, to either loopback
	_, port, _ := net.SplitHostPort(named)
	cfg := &socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "alice"}}
	for _, m := range modes {
		for _, tgt := range []string{"127.0.0.1:" + port, named} {
			t.Run(m.String()+"/"+tgt, func(t *testing.T) {
				cfg := *cfg
				cfg.Mode = m
				d := &socks0.Dialer{ProxyAddr: proxy, Config: &cfg}
				c, err := d.DialContext(t.Context(), "tcp", tgt)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				roundTrip(t, c, []byte("socks4"))
			})
		}
	}
	if len(ids) < 2 || ids[0] != "alice" || ids[1] != wire.MethodUserPass {
		t.Errorf("identity/method %v", ids)
	}
	t.Run("bind", func(t *testing.T) { bindRoundTrip(t, &socks0.Dialer{ProxyAddr: proxy, Config: cfg}, "127.0.0.1:0") })
	t.Run("rejected", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "mallory"}}}
		_, err := d.DialContext(t.Context(), "tcp", "127.0.0.1:"+port)
		if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Version != 4 || re.Reply != wire.Reply4Rejected {
			t.Fatalf("err %v, want 0x5B", err)
		}
	})
}
