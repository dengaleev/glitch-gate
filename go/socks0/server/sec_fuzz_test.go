package server_test

// Security review: fuzz ServeConn with every built-in handler, both versions and several
// authenticators: no panic, bounded ServeConn, no goroutine leak, conn closed.
// Run: go test -fuzz FuzzSecServeConnBuiltins ./server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type fakeResolver struct{}

func (fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	switch {
	case len(host)%3 == 0:
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("8.8.8.8")}, nil
	case len(host)%3 == 1:
		return []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if len(addr)%2 == 0 {
		return []string{"x\x00\r\n.example."}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func secFuzzServer() *server.Server {
	return &server.Server{
		Versions: server.V4 | server.V5,
		Auth: []server.Authenticator{
			server.UserPass{Users: map[string]string{"u": "p", "": ""}},
			server.NoAuth{},
		},
		UserID: func(_ context.Context, id []byte) (any, error) {
			if len(id) == 0 {
				return nil, errors.New("empty")
			}
			return string(id), nil
		},
		HandshakeTimeout: 2 * time.Second,
		ErrorLog:         quietLog,
		Handler: &server.Mux{
			Connect: &server.ConnectHandler{
				Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
					if len(addr)%2 == 0 {
						return nil, &net.OpError{Op: "dial", Err: errors.New("refused")}
					}
					a, b := net.Pipe()
					go func() { _, _ = io.Copy(io.Discard, b); b.Close() }()
					return a, nil
				},
				DialTimeout: 200 * time.Millisecond,
			},
			Bind: &server.BindHandler{AcceptTimeout: 30 * time.Millisecond,
				Listen: func(ctx context.Context, _, _ string) (net.Listener, error) {
					return new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
				}},
			Associate: &server.AssociateHandler{
				IdleTimeout: 30 * time.Millisecond,
				Resolver:    fakeResolver{},
				ListenClient: func(ctx context.Context, network, _ string) (net.PacketConn, error) {
					return new(net.ListenConfig).ListenPacket(ctx, "udp", "127.0.0.1:0")
				},
				ListenTarget: func(ctx context.Context, network, _ string) (net.PacketConn, error) {
					return new(net.ListenConfig).ListenPacket(ctx, "udp", "127.0.0.1:0")
				},
			},
			Resolve: &server.ResolveHandler{Resolver: fakeResolver{}},
		},
	}
}

func FuzzSecServeConnBuiltins(f *testing.F) {
	seeds := [][]byte{
		cat(greeting(0), request(wire.CmdConnect, "1.2.3.4:81"), []byte("early")),
		cat(greeting(2), userPass("u", "p"), request(wire.CmdConnect, "example.com:443")),
		cat(greeting(2), userPass("", ""), request(wire.CmdBind, "0.0.0.0:0")),
		cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")),
		cat(greeting(0), request(wire.CmdTorResolve, "abc:0")),
		cat(greeting(0), request(wire.CmdTorResolvePTR, "8.8.8.8:0")),
		cat(greeting(0), request(wire.CmdTorResolvePTR, "[2001:4860::1]:0")),
		cat(greeting(0), request(0x7f, "1.2.3.4:1")),
		{4, 1, 0, 80, 1, 2, 3, 4, 'i', 'd', 0},
		{4, 2, 0, 80, 0, 0, 0, 1, 'u', 0, 'h', 'o', 's', 't', 0},
		{4, 1, 0, 80, 0, 0, 0, 1, 0, 'h', 0},
		{5, 255},
		{5, 1, 2, 1, 0, 0},
		{},
	}
	for _, s := range seeds {
		f.Add(s, []byte{3, 7, 1})
	}
	s := secFuzzServer()
	f.Fuzz(func(t *testing.T, data, cuts []byte) {
		cli, srv := net.Pipe()
		errc := make(chan error, 1)
		go func() { errc <- s.ServeConn(context.Background(), srv) }()
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = io.Copy(io.Discard, cli) })
		wg.Go(func() {
			last := 0
			for _, c := range cuts {
				if i := last + int(c); i < len(data) {
					if _, err := cli.Write(data[last:i]); err != nil {
						return
					}
					last = i
				}
			}
			_, _ = cli.Write(data[last:])
			cli.Close()
		})
		select {
		case <-errc:
		case <-time.After(8 * time.Second):
			t.Fatalf("ServeConn hangs on %x", data)
		}
		cli.Close()
		wg.Wait()
	})
}
