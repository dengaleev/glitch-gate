package socks0_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func ExampleDialer() {
	d := &socks0.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		Config:    &socks0.Config{Auth: &socks0.UserPass{Username: "u", Password: "p"}},
	}
	client := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
	resp, err := client.Get("https://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}

func ExampleDialer_resolver() {
	// Resolve names locally, like curl's socks5://.
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080", Resolver: net.DefaultResolver}
	conn, err := d.DialContext(context.Background(), "tcp4", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

func ExampleFromURL() {
	u, err := url.Parse("socks5h://user:pass@127.0.0.1:9050")
	if err != nil {
		log.Fatal(err)
	}
	d, err := socks0.FromURL(u)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

func ExampleDialer_DialContext_early() {
	d := &socks0.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		Config:    &socks0.Config{Mode: socks0.ModeEarly},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		log.Fatal(err) // proxy unreachable or bad arguments
	}
	defer conn.Close()

	// The handshake and the request leave in one segment.
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"); err != nil {
		log.Fatal(err)
	}
	// The first Read surfaces handshake errors.
	if _, err := io.Copy(io.Discard, conn); err != nil {
		log.Fatal(err)
	}
}

// Server-first protocols (SMTP, SSH) must start the handshake explicitly.
func ExampleConn_HandshakeContext() {
	raw, err := net.Dial("tcp", "127.0.0.1:1080")
	if err != nil {
		log.Fatal(err)
	}
	c := socks0.Client(raw, "mail.example:25", &socks0.Config{Mode: socks0.ModeEarly})
	defer c.Close()
	if err := c.HandshakeContext(context.Background()); err != nil {
		log.Fatal(err)
	}
	greeting := make([]byte, 512)
	n, err := c.Read(greeting)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", greeting[:n])
}

func ExampleClient() {
	// TLS to the proxy, then SOCKS5 inside it.
	raw, err := tls.Dial("tcp", "proxy.example:1443", nil)
	if err != nil {
		log.Fatal(err)
	}
	c := socks0.Client(raw, "example.com:443", nil)
	defer c.Close()
	if err := c.HandshakeContext(context.Background()); err != nil {
		log.Fatal(err)
	}
	fmt.Println("bound:", c.BoundAddr())
}

func ExampleWithClientTrace() {
	ctx := socks0.WithClientTrace(context.Background(), &socks0.ClientTrace{
		GotReply: func(rep wire.Reply, bound wire.Addr) {
			fmt.Println("reply:", rep, "bound:", bound)
		},
	})
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	conn, err := d.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

// Chaining: the second proxy is reached through the first.
func ExampleDialer_chain() {
	first := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	second := &socks0.Dialer{ProxyAddr: "10.0.0.2:1080", ProxyDial: first.DialContext}
	conn, err := second.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

// Early data over any conn: the handshake and the first Write leave in one
// write, and the first Read consumes the replies.
func ExampleClient_early() {
	client, server := net.Pipe()
	go func() { // a proxy: one read gets the whole first flight
		buf := make([]byte, 512)
		n, _ := server.Read(buf)
		_, target, m, _ := wire.ParseRequest(buf[3:n]) // after the 3-byte greeting
		fmt.Printf("proxy: CONNECT %v, then %q\n", target, buf[3+m:n])
		bound, _ := wire.ParseAddr("192.0.2.1:1080")
		resp := wire.AppendMethodSelection(nil, wire.MethodNoAuth)
		resp, _ = wire.AppendReply(resp, wire.ReplySucceeded, bound)
		server.Write(append(resp, "world"...))
	}()
	c := socks0.Client(client, "example.com:80", &socks0.Config{Mode: socks0.ModeEarly})
	defer c.Close()
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("client:", string(buf), "bound", c.BoundAddr())
	// Output:
	// proxy: CONNECT example.com:80, then "hello"
	// client: world bound 192.0.2.1:1080
}

// Columns for storage and metrics: a stable kind, the stage pending, and a
// string without addresses.
func ExampleHandshakeError() {
	refuse := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			server.Read(make([]byte, 512))
			unspecified, _ := wire.ParseAddr("0.0.0.0:0")
			resp := wire.AppendMethodSelection(nil, wire.MethodNoAuth)
			resp, _ = wire.AppendReply(resp, wire.ReplyConnectionRefused, unspecified)
			server.Write(resp)
			server.Close()
		}()
		return client, nil
	}
	d := &socks0.Dialer{ProxyDial: refuse}
	_, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if he, ok := errors.AsType[*socks0.HandshakeError](err); ok {
		fmt.Printf("kind=%s stage=%s error=%q\n", socks0.KindOf(err), he.Stage, he)
	}
	// Output:
	// kind=reply stage=reply error="socks reply: connection refused"
}

func ExampleParseProxyURL() {
	u, err := url.Parse("socks5+tls://user:p%40ss@proxy.example")
	if err != nil {
		log.Fatal(err)
	}
	p, err := socks0.ParseProxyURL(u)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(p.Addr, "tls:", p.TLS, "resolve locally:", p.ResolveLocally)
	up := p.Config.Auth.(socks0.UserPass)
	fmt.Println(up.Username, up.Password) // percent-decoded
	fmt.Printf("%+v\n", p.Config.Auth)    // formatting hides the password
	// Output:
	// proxy.example:1080 tls: true resolve locally: false
	// user p@ss
	// {user [redacted]}
}

func ExampleTimings() {
	// A probe: ModeSequential, so that Handshake is the CONNECT time.
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080", Config: &socks0.Config{Mode: socks0.ModeSequential}}
	var tm socks0.Timings
	ctx := socks0.WithClientTrace(context.Background(), tm.Trace())
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	log.Printf("proxy %v, handshake %v, total %v, kind %q", tm.ProxyConnect, tm.Handshake, tm.Total, socks0.KindOf(err))
	if err == nil {
		conn.Close()
	}
}

func ExampleIsProxyError() {
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	client := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
	resp, err := client.Get("https://example.com/")
	switch {
	case socks0.IsProxyError(err):
		log.Printf("proxy failed (%s): %v", socks0.KindOf(err), err)
	case err != nil:
		log.Printf("target failed: %v", err)
	default:
		resp.Body.Close()
	}
}

func ExampleConfig_offerNoAuth() {
	// A proxy that may or may not ask for credentials: offer both.
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080", Config: &socks0.Config{
		Mode:        socks0.ModeSequential, // required: the server's choice decides what follows
		Auth:        socks0.UserPass{Username: "user", Password: "secret"},
		OfferNoAuth: true,
	}}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	conn.Close()
}

func ExampleDialer_ListenUDP() {
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	u, err := d.ListenUDP(context.Background(), "udp", "")
	if err != nil {
		log.Fatal(err)
	}
	defer u.Close()
	log.Printf("relay %v, bound %v", u.RelayAddr(), u.BoundAddr())
}

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
