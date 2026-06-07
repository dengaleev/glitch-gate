// Command client shows Go's net.Dialer performing Happy Eyeballs (RFC 8305):
// it races the resolved IPv6 and IPv4 addresses, falling back from a stalled
// IPv6 connect to IPv4 after FallbackDelay. httptrace logs each attempt so the
// fallback is visible.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "http://mock.test:8080", "URL to request; host should resolve to both IPv6 and IPv4")
	fallbackDelay := flag.Duration("fallback-delay", 300*time.Millisecond, "how long to wait for IPv6 before racing IPv4")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Only FallbackDelay is tuned; the dual-stack race itself is Go's default.
	dialer := &net.Dialer{FallbackDelay: *fallbackDelay}
	client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}

	start := time.Now()
	since := func() string { return time.Since(start).Round(time.Millisecond).String() }

	trace := &httptrace.ClientTrace{
		DNSDone: func(info httptrace.DNSDoneInfo) {
			addrs := make([]string, len(info.Addrs))
			for i, a := range info.Addrs {
				addrs[i] = a.String()
			}
			// Sorted per RFC 6724, so IPv6 comes first and is tried first.
			log.Printf("[%8s] resolved: %s", since(), strings.Join(addrs, ", "))
		},
		ConnectStart: func(_, addr string) {
			log.Printf("[%8s] -> connect  %s", since(), addr)
		},
		ConnectDone: func(_, addr string, err error) {
			if err != nil {
				log.Printf("[%8s] <- fail     %s: %v", since(), addr, err)
				return
			}
			log.Printf("[%8s] <- ok       %s", since(), addr)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			log.Printf("[%8s] winner: %s", since(), info.Conn.RemoteAddr())
		},
	}

	ctx := httptrace.WithClientTrace(context.Background(), trace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("requesting %s (fallback-delay=%s)", *url, *fallbackDelay)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	log.Printf("[%8s] %s, served by %s", since(), resp.Status, resp.Header.Get("X-Served-By"))
}
