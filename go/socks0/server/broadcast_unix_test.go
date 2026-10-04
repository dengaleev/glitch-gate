//go:build unix

package server

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// S5: unlike Go's default UDP socket, the target socket cannot broadcast.
func TestNoBroadcast(t *testing.T) {
	opt := func(pc net.PacketConn) int {
		rc, err := pc.(*net.UDPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var v int
		_ = rc.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST) })
		return v
	}
	plain, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	pc, err := listenTarget(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if opt(plain) == 0 || opt(pc) != 0 {
		t.Fatalf("SO_BROADCAST: Go default %d, target socket %d", opt(plain), opt(pc))
	}
	if _, err := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4bcast, Port: 9}); err == nil {
		t.Fatal("broadcast sent")
	}
}
