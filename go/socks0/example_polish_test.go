package socks0_test

import (
	"context"
	"log"
	"net/http"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

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
