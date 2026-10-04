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
