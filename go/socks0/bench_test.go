package socks0_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// Loopback proxy, handshake complete (ModeEarly: first Write and Read), one byte echoed.
func BenchmarkDialContext(b *testing.B) {
	addr := listen(b, proxy{}.serve)
	for _, mode := range modes {
		for _, auth := range []socks0.Authenticator{nil, socks0.UserPass{Username: "user", Password: "pass"}} {
			name := mode.String() + "/noauth"
			if auth != nil {
				name = mode.String() + "/userpass"
			}
			b.Run(name, func(b *testing.B) {
				d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode, Auth: auth}}
				buf := make([]byte, 1)
				b.ReportAllocs()
				for b.Loop() {
					c, err := d.DialContext(b.Context(), "tcp", "example.com:80")
					if err != nil {
						b.Fatal(err)
					}
					if _, err := c.Write(buf); err != nil {
						b.Fatal(err)
					}
					if _, err := io.ReadFull(c, buf); err != nil {
						b.Fatal(err)
					}
					closeNow(c)
				}
			})
		}
	}
}

// closeNow resets: no TIME_WAIT, so the loop keeps its ephemeral ports.
func closeNow(c net.Conn) {
	if sc, ok := c.(*socks0.Conn); ok {
		c = sc.NetConn()
	}
	c.(*net.TCPConn).SetLinger(0)
	c.Close()
}

// replayConn answers every handshake from memory: no syscalls.
type replayConn struct {
	bytes.Reader
	replies []byte
}

func (c *replayConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return nil }
func (c *replayConn) RemoteAddr() net.Addr             { return nil }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }
func (c *replayConn) reset() *replayConn               { c.Reader.Reset(c.replies); return c }
func (c *replayConn) Read(b []byte) (int, error)       { return c.Reader.Read(b) }

func BenchmarkHandshake(b *testing.B) {
	target := mustAddr("example.com:443")
	replies := append([]byte{5, 0}, reply(0, "192.0.2.1:1080")...)
	for _, mode := range modes {
		b.Run(mode.String(), func(b *testing.B) {
			conn := &replayConn{replies: replies}
			cfg := &socks0.Config{Mode: mode}
			b.ReportAllocs()
			for b.Loop() {
				c := socks0.ClientAddr(conn.reset(), target, cfg)
				if err := c.HandshakeContext(context.Background()); err != nil || c.BoundAddr().Port() != 1080 {
					b.Fatal(err)
				}
			}
		})
	}
}

// UDPConn vs raw *net.UDPConn, echo answered on the benchmark goroutine.
func BenchmarkUDPRoundTrip(b *testing.B) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer relay.Close()
	dial := func() *net.UDPConn {
		c, err := net.DialUDP("udp4", nil, relay.LocalAddr().(*net.UDPAddr))
		if err != nil {
			b.Fatal(err)
		}
		return c
	}
	in, buf := make([]byte, 2048), make([]byte, 2048)
	for _, size := range []int{64, 1200} {
		payload := make([]byte, size)
		for _, name := range []string{"raw", "socks0"} {
			b.Run(fmt.Sprintf("%s/%d", name, size), func(b *testing.B) {
				var c net.Conn = dial()
				if name == "socks0" {
					ctl, peer := net.Pipe()
					defer peer.Close()
					c = socks0.NewUDPConn(ctl, c, mustAddr("192.0.2.1:53"))
				}
				defer c.Close()
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := c.Write(payload); err != nil {
						b.Fatal(err)
					}
					n, from, err := relay.ReadFromUDPAddrPort(in)
					if err != nil {
						b.Fatal(err)
					}
					relay.WriteToUDPAddrPort(in[:n], from)
					if _, err := c.Read(buf); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
