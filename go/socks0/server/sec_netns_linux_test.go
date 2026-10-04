//go:build linux

package server_test

// Security regressions that need "public" addresses in a scratch network
// namespace; run with SEC_NETNS=1. In Docker (NET_ADMIN for addresses and
// NAT; NET_RAW, a default, for spoofing):
//
//	docker run --rm --cap-add NET_ADMIN -v "$PWD/..":/src -w /src/socks0 golang:1.27 sh -c '
//	  apt-get update -qq && apt-get install -y -qq iproute2 iptables >/dev/null &&
//	  ip addr add 11.0.0.1/32 dev lo &&   # the proxy public IP A
//	  ip addr add 11.0.0.2/32 dev lo &&   # another public IP of the host, B
//	  ip addr add 10.9.0.1/32 dev lo &&   # a private interface IP (cloud VM)
//	  { iptables -t nat -A OUTPUT -d 11.0.0.9 -j DNAT --to-destination 10.9.0.1 ||
//	    iptables-legacy -t nat -A OUTPUT -d 11.0.0.9 -j DNAT --to-destination 10.9.0.1; } &&  # 1:1 NAT hairpin
//	  ip addr add 11.0.1.1/24 brd 11.0.1.255 dev eth0 &&  # a public subnet
//	  SEC_NETNS=1 go test -race -count=1 -run "^TestSec" -v . ./server'
//
// (from go/socks0; client side: ../sec_client_linux_test.go.)

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func needNetns(t *testing.T) {
	if os.Getenv("SEC_NETNS") == "" {
		t.Skip("needs SEC_NETNS=1 and the namespace setup in the file header")
	}
}

func serveOn(t *testing.T, s *server.Server, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return ln.Addr().String()
}

func connectVia(t *testing.T, proxy, target string) (net.Conn, wire.Reply) {
	t.Helper()
	c := dial(t, proxy)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target)))
	expect(t, c, []byte{5, 0})
	rep, _, err := wire.ReadReply(c, wire.CmdConnect)
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	return c, rep
}

// L3: another public IP of the proxy's host is refused before connecting, open or closed.
func TestSec_OwnHostNoPortScanOracleNetns(t *testing.T) {
	needNetns(t)
	svc, err := net.Listen("tcp", "0.0.0.0:0") // e.g. Redis, firewalled from outside
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	open := svc.Addr().(*net.TCPAddr).Port
	closedLn, _ := net.Listen("tcp", "0.0.0.0:0")
	closed := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()

	proxy := serveOn(t, &server.Server{ErrorLog: quietLog}, "11.0.0.1:0") // zero value: DefaultFilter
	_, repOpen := connectVia(t, proxy, net.JoinHostPort("11.0.0.2", strconv.Itoa(open)))
	_, repClosed := connectVia(t, proxy, net.JoinHostPort("11.0.0.2", strconv.Itoa(closed)))
	time.Sleep(100 * time.Millisecond)
	if repOpen != wire.ReplyNotAllowed || repClosed != wire.ReplyNotAllowed || accepted.Load() != 0 {
		t.Fatalf("open port → %v, closed → %v, service accepted %d; want 02, 02, 0", repOpen, repClosed, accepted.Load())
	}
}

// M2: behind 1:1 NAT only SelfAddrs stops a CONNECT to the public IP from looping.
func TestSec_NATHairpinLoopDenied(t *testing.T) {
	needNetns(t)
	var conns atomic.Int32
	s := &server.Server{ErrorLog: quietLog, SelfAddrs: []netip.Prefix{netip.MustParsePrefix("11.0.0.9/32")},
		ConnState: func(_ net.Conn, st server.ConnState) {
			if st == server.StateNew {
				conns.Add(1)
			}
		}}
	ip := os.Getenv("SEC_PRIVATE_IP") // two-container setup: proxy's private IP behind a NAT gateway
	if ip == "" {
		ip = "10.9.0.1"
	}
	proxy := serveOn(t, s, net.JoinHostPort(ip, "0"))
	_, port, _ := net.SplitHostPort(proxy)
	if _, rep := connectVia(t, proxy, net.JoinHostPort("11.0.0.9", port)); rep != wire.ReplyNotAllowed {
		t.Fatalf("CONNECT to the proxy's public IP: %v, want 02", rep)
	}
	time.Sleep(100 * time.Millisecond)
	if n := conns.Load(); n != 1 {
		t.Fatalf("the proxy saw %d conns for one client conn", n)
	}
}

// A directed broadcast passes DefaultFilter but SO_BROADCAST is cleared; limited broadcast is denied.
func TestSecOK_UDPNoDirectedBroadcast(t *testing.T) {
	needNetns(t)
	sink, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	port := uint16(sink.LocalAddr().(*net.UDPAddr).Port)
	var got atomic.Int32
	go func() {
		b := make([]byte, 2048)
		for {
			if _, _, err := sink.ReadFrom(b); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	var mu sync.Mutex
	var drops []string
	s := &server.Server{ErrorLog: quietLog, Handler: &server.AssociateHandler{}, Trace: &server.ServerTrace{
		Dropped: func(_ context.Context, from netip.AddrPort, err error) {
			mu.Lock()
			defer mu.Unlock()
			drops = append(drops, err.Error())
		},
	}}
	proxy := serveOn(t, s, "11.0.0.1:0")
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")))
	expect(t, c, []byte{5, 0})
	rep, bound := readReply(t, c, wire.CmdUDPAssociate)
	if rep != 0 {
		t.Fatal(rep)
	}
	u, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("11.0.0.1")}, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP(), bound.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for _, dst := range []string{"11.0.1.255", "255.255.255.255"} {
		h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(dst), port)))
		_, _ = u.Write(append(h, "bcast"...))
	}
	time.Sleep(300 * time.Millisecond)
	if got.Load() != 0 {
		t.Fatal("broadcast relayed")
	}
}

func spoofUDP(t *testing.T, src, dst netip.AddrPort, payload []byte) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		t.Skip("raw socket:", err)
	}
	defer syscall.Close(fd)
	ulen := 8 + len(payload)
	pkt := []byte{0x45, 0, byte((20 + ulen) >> 8), byte(20 + ulen), 0, 0, 0, 0, 64, 17, 0, 0}
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	pkt = append(append(pkt, s4[:]...), d4[:]...)
	pkt = binary.BigEndian.AppendUint16(pkt, src.Port())
	pkt = binary.BigEndian.AppendUint16(pkt, dst.Port())
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(ulen))
	pkt = append(pkt, 0, 0) // no UDP checksum (IPv4)
	pkt = append(pkt, payload...)
	if err := syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: d4}); err != nil {
		t.Fatal(err)
	}
}

// L4: a host forging the client's IP races for the source lock; a client sending its port as DST wins.
func TestSec_UDPSpoofedFirstDatagramDropped(t *testing.T) {
	needNetns(t)
	echo := echoUDP(t, "11.0.0.2:0")
	var mu sync.Mutex
	var drops []string
	s := &server.Server{ErrorLog: quietLog, Handler: &server.AssociateHandler{Filter: server.AllowAll},
		Trace: &server.ServerTrace{Dropped: func(_ context.Context, from netip.AddrPort, err error) {
			mu.Lock()
			defer mu.Unlock()
			drops = append(drops, from.String()+": "+err.Error())
		}}}
	proxy := serveOn(t, s, "11.0.0.1:0")
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("11.0.0.2")}) // victim's UDP socket
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("11.0.0.2")}} // victim
	c, err := d.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, fmt.Sprintf("0.0.0.0:%d", u.LocalAddr().(*net.UDPAddr).Port))))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdUDPAssociate)
	relay := netip.AddrPortFrom(bound.IP(), bound.Port())

	hdr, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(echo.LocalAddr().(*net.UDPAddr).AddrPort()))
	spoofUDP(t, netip.MustParseAddrPort("11.0.0.2:6666"), relay, append(hdr, "attacker"...)) // forged, first
	time.Sleep(50 * time.Millisecond)
	_, _ = u.WriteToUDPAddrPort(append(hdr, "victim"...), relay)
	_ = u.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, rerr := u.Read(make([]byte, 100))
	mu.Lock()
	defer mu.Unlock()
	if rerr != nil || len(drops) != 1 {
		t.Fatalf("victim read: %v; drops: %v", rerr, drops)
	}
}
