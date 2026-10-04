package socks0_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func ExampleDialer_DialContext_udp() {
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	// A UDPConn connected to the target, like net.DialUDP: an NTP query.
	conn, err := d.DialContext(context.Background(), "udp", "pool.ntp.org:123")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x23 // version 4, client mode
	if _, err := conn.Write(req); err != nil {
		log.Fatal(err)
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		log.Fatal(err)
	}
}

func ExampleDialer_DialContext_dns() {
	// DNS through the proxy, over UDP with TCP fallback (truncation). The
	// stdlib resolver dials once per query: each costs a UDP association
	// (a TCP control conn and a UDP socket). The resolver passes the
	// system's nameserver, which is likely unreachable from the proxy, so
	// name one explicitly.
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, "1.1.1.1:53")
		},
	}
	ips, err := r.LookupNetIP(context.Background(), "ip4", "example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ips)
}

func ExampleDialer_ListenPacket() {
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	pc, err := d.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()
	uc := pc.(*socks0.UDPConn)
	// Room for a payload in a 1500-byte path MTU over IPv4.
	target, _ := wire.ParseAddr("192.0.2.1:443")
	payload := make([]byte, 1500-20-8-wire.UDPHeaderLen(target))
	if _, err := uc.WriteToAddr(payload, target); err != nil {
		log.Fatal(err)
	}
	select {
	case <-uc.Done():
		fmt.Println("association ended:", uc.Err())
	default:
	}
}

func ExampleDialer_Listen() {
	// FTP active mode: the server connects back to us through the proxy.
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	ln, err := d.Listen(context.Background(), "tcp", "198.51.100.21:20") // the FTP server's data address
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Println("PORT for", ln.Addr()) // send PORT/EPRT with this address
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

func ExampleDialer_LookupHost() {
	tor := &socks0.Dialer{ProxyAddr: "127.0.0.1:9050"}
	addrs, err := tor.LookupHost(context.Background(), "example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(addrs)
	// Resolve through Tor, connect through another proxy.
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080", Resolver: tor}
	conn, err := d.DialContext(context.Background(), "tcp4", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

func ExampleFastOpenDial() {
	d := &socks0.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		ProxyDial: socks0.FastOpenDial(&net.Dialer{KeepAlive: 15 * time.Second}),
		Config:    &socks0.Config{Mode: socks0.ModeEarly},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		log.Fatal(err) // errors.ErrUnsupported where TFO is not
	}
	defer conn.Close()
}

func ExampleConfig_socks4() {
	d := &socks0.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		Config:    &socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "userid"}},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80") // SOCKS4a
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
