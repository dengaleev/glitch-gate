//go:build linux

package socks0_test

// Needs server/sec_netns_linux_test.go's namespaces (proxy 11.0.0.1) and SEC_NETNS=1.

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Finding L2.
func TestSec_ClientUDPRejectsHostileBNDNetns(t *testing.T) {
	if os.Getenv("SEC_NETNS") == "" {
		t.Skip("needs SEC_NETNS=1 and the namespace setup in server/sec_netns_linux_test.go")
	}
	for _, tc := range []struct{ sinkAddr, bnd string }{
		{"127.0.0.1:0", "127.0.0.1"},
		{"0.0.0.0:0", "255.255.255.255"},
		{"0.0.0.0:0", "11.0.1.255"}, // directed broadcast: SO_BROADCAST is cleared
	} {
		pc, err := net.ListenPacket("udp4", tc.sinkAddr)
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		ln, err := net.Listen("tcp", "11.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			if _, err := wire.ReadGreeting(c); err != nil {
				return
			}
			if _, _, err := wire.ReadRequest(c); err != nil {
				return
			}
			rep, _ := wire.AppendReply([]byte{5, 0}, 0, wire.AddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(tc.bnd), port)))
			_, _ = c.Write(rep)
			b := make([]byte, 1)
			_, _ = c.Read(b)
		}()
		d := &socks0.Dialer{ProxyAddr: ln.Addr().String()}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := d.DialContext(ctx, "udp", "9.9.9.9:53")
		cancel()
		if err == nil {
			_, err = c.Write([]byte("private-dns-query"))
			c.Close()
		}
		_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, _, rerr := pc.ReadFrom(make([]byte, 100)); rerr == nil {
			t.Errorf("BND %s: a %d-byte client datagram was delivered there (err %v)", tc.bnd, n, err)
		}
		if err == nil {
			t.Errorf("BND %s: no error", tc.bnd)
		}
		pc.Close()
		ln.Close()
	}
}
