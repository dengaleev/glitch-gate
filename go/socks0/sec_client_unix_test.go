//go:build unix

package socks0_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// Finding L2: a directed broadcast BND is unrecognizable; the socket must refuse broadcast.
func TestSec_ClientRelayNoBroadcast(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{}.serve)}
	c, err := d.DialContext(t.Context(), "udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, err := c.(*socks0.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	v := -1
	_ = rc.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST) })
	if v != 0 {
		t.Fatalf("SO_BROADCAST %d on the relay socket", v)
	}
	plain, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	prc, _ := plain.(*net.UDPConn).SyscallConn()
	_ = prc.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST) })
	if v == 0 {
		t.Log("Go no longer sets SO_BROADCAST by default")
	}
}
