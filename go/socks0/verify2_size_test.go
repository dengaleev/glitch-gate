package socks0_test

// Linux loopback takes exactly 65507 (IPv4) / 65527 (IPv6) bytes of UDP
// payload: socks0's largest must pass, one more fail before any syscall.

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestV2MessageSizeExact(t *testing.T) {
	name255 := strings.Repeat("a", 251) + ".com"
	for _, relay := range []string{"udp4", "udp6"} {
		for _, target := range []string{"192.0.2.1:9", "[2001:db8::1]:9", "x:9", name255 + ":9"} {
			for _, path := range []string{"dial", "listen", "relaylisten"} {
				t.Run(relay+"/"+target[:min(len(target), 16)]+"/"+path, func(t *testing.T) {
					if relay == "udp6" && !hasIPv6() {
						t.Skip("no IPv6")
					}
					to := mustAddr(target)
					ipHdr := 20
					if relay == "udp6" {
						ipHdr = 0
					}
					max := 65535 - 8 - ipHdr - wire.UDPHeaderLen(to)
					raw := make(chan []byte, 8)
					d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{network: relay, raw: raw}.serve)}
					if path == "relaylisten" {
						d.RelayListen = func(ctx context.Context, network, laddr string) (net.PacketConn, error) {
							return net.ListenPacket(network, laddr)
						}
					}
					var write func([]byte) (int, error)
					if path == "dial" {
						c, err := d.DialContext(t.Context(), "udp", target)
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						write = c.Write
					} else {
						pc, err := d.ListenPacket(t.Context(), "udp", "")
						if err != nil {
							t.Fatal(err)
						}
						defer pc.Close()
						write = func(b []byte) (int, error) { return pc.(*socks0.UDPConn).WriteToAddr(b, to) }
					}
					_, err := write(make([]byte, max+1))
					if !errors.Is(err, eMsgSize) {
						t.Errorf("payload max+1=%d: %v; want EMSGSIZE", max+1, err)
					}
					if oe, ok := err.(*net.OpError); !ok || oe.Op != "write" {
						t.Errorf("EMSGSIZE error shape: %#v", err)
					}
					if runtime.GOOS != "linux" {
						return
					}
					n, err := write(make([]byte, max))
					if err != nil || n != max {
						t.Fatalf("payload max=%d: %d, %v", max, n, err)
					}
					select {
					case b := <-raw:
						if len(b) != max+wire.UDPHeaderLen(to) {
							t.Errorf("proxy got %d bytes, want %d", len(b), max+wire.UDPHeaderLen(to))
						}
					case <-time.After(2 * time.Second):
						t.Error("proxy got nothing")
					}
				})
			}
		}
	}
}
