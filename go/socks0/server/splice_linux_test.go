package server_test

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
)

func spliceOS() bool { return true }

// pipeFDs: Go pools splice pipes, so a relay that spliced leaves some open.
func pipeFDs(t testing.TB) int {
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	n := 0
	for _, e := range es {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.HasPrefix(l, "pipe:") {
			n++
		}
	}
	return n
}

// Strace-free evidence of splice; TestDelegation shows the path.
func TestSpliceUsed(t *testing.T) {
	echo := echoTCP(t, "127.0.0.1:0")
	before := pipeFDs(t)
	c := dial(t, serve(t, open()))
	m, _ := newMessage("", "", echo, payload()[:1<<20])
	go func() { _, _ = c.Write(m.wire); _ = c.CloseWrite() }()
	if err := s5ReadReplies(c, ""); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || len(got) != 1<<20 {
		t.Fatalf("%d bytes, %v", len(got), err)
	}
	if after := pipeFDs(t); after <= before && before == 0 {
		t.Fatalf("no splice pipes (%d before, %d after)", before, after)
	}
}

// S8
func TestUserTimeout(t *testing.T) {
	for _, tt := range []struct {
		set  time.Duration
		want int
	}{{0, 120000}, {5 * time.Second, 5000}, {-1, 0}} {
		_, cliSrv := tcpPair(t)
		tgtSrv, _ := tcpPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		res := startRelay(&server.Relayer{UserTimeout: tt.set}, ctx, cliSrv, tgtSrv)
		time.Sleep(50 * time.Millisecond)
		for _, c := range []*net.TCPConn{cliSrv, tgtSrv} {
			rc, _ := c.SyscallConn()
			var v int
			var gerr error
			_ = rc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, 0x12) })
			if gerr != nil || v != tt.want {
				t.Errorf("UserTimeout %v: TCP_USER_TIMEOUT %d, %v; want %d", tt.set, v, gerr, tt.want)
			}
		}
		cancel()
		waitRelay(t, res)
	}
}
