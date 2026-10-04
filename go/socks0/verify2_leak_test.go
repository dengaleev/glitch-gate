package socks0_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func openFDs(t *testing.T) int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		if es, err := os.ReadDir(dir); err == nil {
			return len(es)
		}
	}
	t.Skip("cannot count fds")
	return 0
}

func TestV2NoLeaksOnErrors(t *testing.T) {
	errDial := errors.New("relay dial refused by test")
	zero := func(netip.AddrPort) wire.Addr { return mustAddr("127.0.0.1:0") }
	unspec := func(ap netip.AddrPort) wire.Addr { return mustAddr("0.0.0.0:" + itoa(int(ap.Port()))) }
	good := listen(t, udpProxy{}.serve)
	rep7 := listen(t, udpProxy{rep: wire.ReplyCommandNotSupported}.serve)
	port0 := listen(t, udpProxy{bnd: zero}.serve)
	unspecP := listen(t, udpProxy{bnd: unspec}.serve)
	hang := listen(t, func(c net.Conn) {
		buf := make([]byte, 100)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	})
	bindEOF := bind5(t, func(c net.Conn) { c.Write(reply(0, "127.0.0.1:5555")) })
	tor := listen(t, torProxy{reply: []byte{5, 4, 0, 0, 0, 0, 0, 0, 0, 0}}.serve)
	cases := []struct {
		name string
		f    func(ctx context.Context) error
	}{
		{"REP 07", func(ctx context.Context) error {
			_, err := (&socks0.Dialer{ProxyAddr: rep7}).ListenPacket(ctx, "udp", "")
			return err
		}},
		{"BND port 0", func(ctx context.Context) error {
			_, err := (&socks0.Dialer{ProxyAddr: port0}).ListenPacket(ctx, "udp", "")
			return err
		}},
		{"RelayDial error", func(ctx context.Context) error {
			d := &socks0.Dialer{ProxyAddr: good, RelayDial: func(context.Context, string, string) (net.Conn, error) { return nil, errDial }}
			_, err := d.DialContext(ctx, "udp", "192.0.2.1:9")
			return err
		}},
		{"RelayDial conn+error", func(ctx context.Context) error {
			d := &socks0.Dialer{ProxyAddr: good, RelayDial: func(ctx context.Context, n, a string) (net.Conn, error) {
				c, _ := new(net.Dialer).DialContext(ctx, n, a)
				return c, errDial
			}}
			_, err := d.DialContext(ctx, "udp", "192.0.2.1:9")
			return err
		}},
		{"RelayListen conn+error", func(ctx context.Context) error {
			d := &socks0.Dialer{ProxyAddr: good, RelayListen: func(ctx context.Context, n, a string) (net.PacketConn, error) {
				c, _ := net.ListenPacket(n, a)
				return c, errDial
			}}
			_, err := d.ListenPacket(ctx, "udp", "")
			return err
		}},
		{"RelayDial nil,nil", func(ctx context.Context) error {
			d := &socks0.Dialer{ProxyAddr: good, RelayDial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}
			_, err := d.ListenPacket(ctx, "udp", "")
			return err
		}},
		{"substitution DNS failure", func(ctx context.Context) error {
			d := &socks0.Dialer{ProxyAddr: "no-such-host.invalid:1", ProxyDial: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, n, unspecP)
			}}
			_, err := d.ListenPacket(ctx, "udp", "")
			return err
		}},
		{"ctx timeout in handshake", func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()
			_, err := (&socks0.Dialer{ProxyAddr: hang}).ListenPacket(ctx, "udp", "")
			return err
		}},
		{"BIND EOF before reply 2", func(ctx context.Context) error {
			ln, err := (&socks0.Dialer{ProxyAddr: bindEOF}).Listen(ctx, "tcp", "192.0.2.1:1")
			if err != nil {
				return err
			}
			_, err = ln.Accept()
			return err
		}},
		{"BIND ctx timeout", func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()
			_, err := (&socks0.Dialer{ProxyAddr: hang}).Listen(ctx, "tcp", "192.0.2.1:1")
			return err
		}},
		{"RESOLVE REP 04", func(ctx context.Context) error {
			_, err := (&socks0.Dialer{ProxyAddr: tor}).LookupHost(ctx, "nx.example")
			return err
		}},
		{"RESOLVE timeout", func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()
			_, err := (&socks0.Dialer{ProxyAddr: hang}).LookupHost(ctx, "nx.example")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.f(t.Context()) // warm up (resolver, listeners)
			time.Sleep(20 * time.Millisecond)
			runtime.GC()
			fds, gs := openFDs(t), runtime.NumGoroutine()
			for range 10 {
				if err := tc.f(t.Context()); err == nil {
					t.Fatal("no error")
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				runtime.GC()
				nf, ng := openFDs(t), runtime.NumGoroutine()
				if nf <= fds && ng <= gs+1 {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("fds %d → %d, goroutines %d → %d", fds, nf, gs, ng)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func itoa(n int) string {
	return string(appendInt(nil, n))
}

func appendInt(b []byte, n int) []byte {
	if n >= 10 {
		b = appendInt(b, n/10)
	}
	return append(b, byte('0'+n%10))
}
