package server_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// A production server: user/pass, CONNECT and UDP, public targets only.
func Example() {
	s := &server.Server{
		Addr: "localhost:1080",
		Auth: []server.Authenticator{server.UserPass{Users: map[string]string{"alice": "secret"}}},
		Handler: &server.Mux{
			Connect:   &server.ConnectHandler{},
			Associate: &server.AssociateHandler{},
		},
	}
	go func() {
		if err := s.ListenAndServe(); !errors.Is(err, server.ErrServerClosed) {
			log.Print(err)
		}
	}()
	// …
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.Shutdown(ctx)
}

// A handler chaining to an upstream proxy chosen by identity, with the early data in its first write.
func ExampleHandlerFunc() {
	upstreams := map[any]*socks0.Dialer{
		"alice": {ProxyAddr: "upstream-a:1080", Config: &socks0.Config{Mode: socks0.ModeEarly}},
	}
	h := server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
		up, ok := upstreams[r.Identity]
		if !ok {
			return server.ErrNotAllowed // replied 02
		}
		t, err := up.DialContext(ctx, "tcp", r.Addr.String())
		if err != nil {
			return err // replied as ReplyFor(err); an upstream *socks0.ReplyError keeps its code
		}
		c, err := r.Reply(wire.ReplySucceeded, wire.Addr{})
		if err != nil {
			t.Close()
			return err
		}
		_, _, err = server.Relay(ctx, c, t)
		return err
	})
	_ = &server.Server{Handler: h}
}

// Per-IP limits and brute-force throttling live in Admit, which runs before any byte is read.
func ExampleServer_admit() {
	var mu sync.Mutex
	perIP := map[netip.Addr]int{}
	s := &server.Server{
		Auth: []server.Authenticator{server.UserPass{Users: map[string]string{"alice": "secret"}}},
		Admit: func(ctx context.Context, c net.Conn) (func(), error) {
			ip := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
			mu.Lock()
			defer mu.Unlock()
			if perIP[ip] >= 8 {
				return nil, errors.New("too many conns from one IP")
			}
			perIP[ip]++
			return func() {
				mu.Lock()
				defer mu.Unlock()
				if perIP[ip]--; perIP[ip] == 0 {
					delete(perIP, ip)
				}
			}, nil
		},
		Trace: &server.ServerTrace{AuthDone: func(ctx context.Context, m wire.Method, _ any, err error) {
			if err != nil {
				time.Sleep(time.Second) // a failed login holds its conn, and its Admit slot, a while
			}
		}},
	}
	_ = s
}

// A port policy, such as no SMTP, goes in Allow; IP policy in a Filter.
func ExampleServer_allow() {
	s := &server.Server{
		Allow: func(ctx context.Context, r *server.Request) error {
			if r.Command == wire.CmdConnect && r.Addr.Port() == 25 {
				return server.ErrNotAllowed
			}
			return nil
		},
	}
	_ = s
}

// SOCKS over TLS: ServeConn with tls.Server, or Serve with tls.NewListener.
func ExampleServer_ServeConn() {
	cfg := &tls.Config{ /* Certificates: … */ }
	ln, err := net.Listen("tcp", "localhost:1443")
	if err != nil {
		return
	}
	s := &server.Server{Auth: []server.Authenticator{server.UserPass{Users: map[string]string{"alice": "secret"}}}}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { _ = s.ServeConn(context.Background(), tls.Server(c, cfg)) }()
	}
}

// A Filter that also denies this host's other addresses, for multi-homed servers.
func ExampleFilter() {
	own := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}
	f := func(r *server.Request, network string, a netip.AddrPort) error {
		for _, ip := range own {
			if a.Addr() == ip {
				return &server.DeniedError{Addr: a, Reason: "own address"}
			}
		}
		return server.DefaultFilter(r, network, a)
	}
	_ = &server.ConnectHandler{Filter: f}
}
