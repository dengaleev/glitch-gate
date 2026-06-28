// Command socks5-pipelining-bench compares a regular (sequential) SOCKS5
// handshake against a pipelined one (greeting + auth + request in a single
// write) by fetching a URL through a SOCKS5 proxy N times each and reporting a
// per-phase latency breakdown (proxy DNS, TCP connect, SOCKS5 handshake, TLS,
// server wait, TTFB, TTLB) using net/http/httptrace.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	target := flag.String("target", "https://www.cloudflare.com/cdn-cgi/trace", "destination URL to fetch through the proxy (Cloudflare trace by default)")
	n := flag.Int("n", 3, "number of measured requests per client")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	noWarmup := flag.Bool("no-warmup", false, "skip the (unmeasured) warm-up request")
	flag.Usage = usage
	flag.Parse()

	px, err := parseProxy(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		usage()
		os.Exit(2)
	}
	auth := px.User.Username() != ""
	ctx := context.Background()

	fmt.Println("SOCKS5 handshake benchmark — regular vs pipelined")
	fmt.Printf("proxy : %s (auth: %s)\n", px.Redacted(), yesno(auth))
	fmt.Printf("target: %s\n", *target)
	fmt.Printf("runs  : %d each, interleaved, HTTP/1.1, keep-alive disabled\n", *n)

	if !*noWarmup {
		_, body, err := measure(ctx, *target, px, false, *insecure, *timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nwarm-up request failed: %v\n", err)
			os.Exit(1)
		}
		if s := sample(body); s != "" {
			fmt.Printf("sample: %s\n", s)
		}
	}
	fmt.Print("\nAll times in milliseconds.\n\n")

	var reg, pip []result
	for i := 0; i < *n; i++ {
		// Interleave regular/pipelined so neither eats network warm-up bias.
		if pt, _, err := measure(ctx, *target, px, false, *insecure, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "regular run %d failed: %v\n", i+1, err)
		} else {
			reg = append(reg, pt.result())
		}
		if pt, _, err := measure(ctx, *target, px, true, *insecure, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "pipelined run %d failed: %v\n", i+1, err)
		} else {
			pip = append(pip, pt.result())
		}
	}

	if len(reg) == 0 || len(pip) == 0 {
		fmt.Fprintln(os.Stderr, "no successful runs to compare")
		os.Exit(1)
	}

	renderRuns(os.Stdout, "Regular (sequential handshake)", reg)
	renderRuns(os.Stdout, "Pipelined (greeting+auth+request in one write)", pip)
	renderComparison(os.Stdout, mean(reg), mean(pip))
	fmt.Printf("\n%s\n", footnote(auth))
}

// measure performs one full request and returns its phase trace and body.
func measure(ctx context.Context, target string, px *url.URL, pipelined, insecure bool, timeout time.Duration) (*phaseTrace, []byte, error) {
	pt := &phaseTrace{}
	tr := &http.Transport{
		DialContext:       makeDialContext(px, pipelined, pt),
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		// Force HTTP/1.1 for clean, comparable trace semantics.
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	defer tr.CloseIdleConnections()

	ct := &httptrace.ClientTrace{
		TLSHandshakeStart:    func() { pt.tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { pt.tlsDone = time.Now() },
		GotFirstResponseByte: func() { pt.firstByte = time.Now() },
	}

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(rctx, ct), http.MethodGet, target, nil)
	if err != nil {
		return pt, nil, err
	}
	req.Header.Set("User-Agent", "socks5-pipelining-bench")

	pt.start = time.Now()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return pt, nil, err
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	pt.done = time.Now()
	if readErr != nil {
		return pt, body, fmt.Errorf("read body: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return pt, body, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return pt, body, nil
}

func parseProxy(arg string) (*url.URL, error) {
	if arg == "" {
		return nil, fmt.Errorf("missing SOCKS5 proxy URL argument")
	}
	u, err := url.Parse(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", arg, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("proxy URL must use the socks5:// (or socks5h://) scheme, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("proxy URL %q has no host", arg)
	}
	return u, nil
}

func sample(body []byte) string {
	var ip, colo string
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			ip = v
		}
		if v, ok := strings.CutPrefix(line, "colo="); ok {
			colo = v
		}
	}
	var parts []string
	if ip != "" {
		parts = append(parts, "ip="+ip)
	}
	if colo != "" {
		parts = append(parts, "colo="+colo)
	}
	return strings.Join(parts, " ")
}

func footnote(auth bool) string {
	saved := "1 round trip (no-auth)"
	if auth {
		saved = "2 round trips (user/pass)"
	}
	return "Note: SOCKS5 is the only phase pipelining changes — it removes " + saved + ".\n" +
		"TTFB/TTLB should improve by ~the same absolute amount; DNS/TCP/TLS/Wait are unaffected."
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func usage() {
	fmt.Fprint(os.Stderr, `socks5-pipelining-bench — compare regular vs pipelined SOCKS5 handshakes

Usage:
  socks5-pipelining-bench [flags] socks5://[user:pass@]host:port

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\nExample:\n  socks5-pipelining-bench -n 5 socks5://user:pass@127.0.0.1:1080\n")
}
