//go:build linux

package server_test

// Tests that need "public" addresses in a scratch network namespace; they skip unless SEC_NETNS=1.
// In Docker (NET_ADMIN for addresses and NAT; NET_RAW, a default, for spoofing), from go/socks0:
//
//	docker run --rm --cap-add NET_ADMIN -v "$PWD/..":/src -w /src/socks0 golang:1.27 sh -c '
//	  apt-get update -qq && apt-get install -y -qq iproute2 iptables >/dev/null &&
//	  ip addr add 11.0.0.1/32 dev lo &&   # the proxy public IP A
//	  ip addr add 11.0.0.2/32 dev lo &&   # another public IP of the host, B
//	  ip addr add 10.9.0.1/32 dev lo &&   # a private interface IP (cloud VM)
//	  { iptables -t nat -A OUTPUT -d 11.0.0.9 -j DNAT --to-destination 10.9.0.1 ||
//	    iptables-legacy -t nat -A OUTPUT -d 11.0.0.9 -j DNAT --to-destination 10.9.0.1; } &&  # 1:1 NAT hairpin
//	  ip addr add 11.0.1.1/24 brd 11.0.1.255 dev eth0 &&  # a public subnet
//	  SEC_NETNS=1 go test -race -count=1 -run "Netns$" -v . ./server'
//
// The root package's client-side netns tests share this setup.

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
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

// Another public IP of the proxy's host is refused before connecting, open port or closed.
func TestOwnHostNoPortScanOracleNetns(t *testing.T) {
	needNetns(t)
	portScan(t, serveLn(t, &server.Server{ErrorLog: quietLog}, listen(t, "11.0.0.1:0")), "0.0.0.0", "11.0.0.2")
}

// Behind 1:1 NAT only SelfAddrs stops a CONNECT to the public IP from looping.
func TestSelfAddrsNATHairpinNetns(t *testing.T) {
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
	proxy := serveLn(t, s, listen(t, net.JoinHostPort(ip, "0")))
	_, port, _ := net.SplitHostPort(proxy)
	if _, rep, _ := ask(t, proxy, request(wire.CmdConnect, net.JoinHostPort("11.0.0.9", port))); rep != wire.ReplyNotAllowed {
		t.Fatalf("CONNECT to the proxy's public IP: %v, want 02", rep)
	}
	time.Sleep(100 * time.Millisecond)
	if n := conns.Load(); n != 1 {
		t.Fatalf("the proxy saw %d conns for one client conn", n)
	}
}

// A directed broadcast passes DefaultFilter but SO_BROADCAST is cleared; limited broadcast is denied.
func TestUDPNoBroadcastNetns(t *testing.T) {
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
	s := &server.Server{ErrorLog: quietLog, Handler: &server.AssociateHandler{}, Trace: (&drops{}).trace()}
	_, relay := assoc(t, serveLn(t, s, listen(t, "11.0.0.1:0")), "0.0.0.0:0")
	u, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("11.0.0.1")}, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for _, dst := range []string{"11.0.1.255", "255.255.255.255"} {
		_, _ = u.Write(dgram(netip.AddrPortFrom(netip.MustParseAddr(dst), port), "bcast"))
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

// A host forging the client's IP races for the source lock; a client sending its port as DST wins.
func TestUDPSpoofedFirstDatagramDroppedNetns(t *testing.T) {
	needNetns(t)
	echo := echoUDP(t, "11.0.0.2:0")
	d := &drops{}
	s := &server.Server{ErrorLog: quietLog, Handler: &server.AssociateHandler{Filter: server.AllowAll}, Trace: d.trace()}
	proxy := serveLn(t, s, listen(t, "11.0.0.1:0"))
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("11.0.0.2")}) // victim's UDP socket
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	dl := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("11.0.0.2")}} // victim
	c, err := dl.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(cat(greeting(0), request(wire.CmdUDPAssociate, fmt.Sprintf("0.0.0.0:%d", u.LocalAddr().(*net.UDPAddr).Port))))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdUDPAssociate)
	relay := netip.AddrPortFrom(bound.IP(), bound.Port())

	to := apOf(echo.LocalAddr())
	spoofUDP(t, netip.MustParseAddrPort("11.0.0.2:6666"), relay, dgram(to, "attacker")) // forged, first
	time.Sleep(50 * time.Millisecond)
	_, _ = u.WriteToUDPAddrPort(dgram(to, "victim"), relay)
	_ = u.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, rerr := u.Read(make([]byte, 100))
	if ds := d.list(); rerr != nil || len(ds) != 1 {
		t.Fatalf("victim read: %v; drops: %v", rerr, ds)
	}
}
