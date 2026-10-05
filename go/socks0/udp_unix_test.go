//go:build unix

package socks0_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// A directed broadcast BND is unrecognizable: the relay socket must refuse broadcast.
func TestUDPRelayNoBroadcast(t *testing.T) {
	c, err := (&socks0.Dialer{ProxyAddr: listenProxy(t)}).DialContext(t.Context(), "udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	broadcast := func(c syscall.Conn) int {
		rc, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		v := -1
		rc.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST) })
		return v
	}
	if v := broadcast(c.(*socks0.UDPConn)); v != 0 {
		t.Fatalf("SO_BROADCAST %d on the relay socket", v)
	}
	plain, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if broadcast(plain.(*net.UDPConn)) == 0 {
		t.Log("Go no longer sets SO_BROADCAST by default")
	}
}
