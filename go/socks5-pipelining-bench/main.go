// Command socks5-pipelining-bench compares the SOCKS5 tunnel-setup strategies —
// regular (sequential), pipelined (greeting+auth+CONNECT in one write), 0-rtt
// (that write also carries the first application payload), and, with -tfo,
// 0-rtt+TCP Fast Open (that write carried in the SYN) — by fetching a URL
// through a SOCKS5 proxy N times each and reporting a per-phase latency
// breakdown (proxy DNS, TCP connect, SOCKS5 handshake, TLS, server wait, TTFB,
// TTLB) via net/http/httptrace. For the deferred (0-rtt) modes the handshake
// folds into the first write, so the SOCKS5 column is ~0 and TTFB/TTLB is the
// metric to compare.
package main

import (
	"context"
	"crypto/tls"
	"errors"
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
	tfo := flag.Bool("tfo", false, "also measure a 0-rtt+TCP Fast Open client (needs OS + proxy TFO support; falls back otherwise)")
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

	fmt.Printf("proxy:  %s (auth: %s)\n", px.Redacted(), yesno(auth))
	fmt.Printf("target: %s\n", *target)

	modes := []mode{modeRegular, modePipelined, modeZeroRTT}
	if *tfo {
		modes = append(modes, modeZeroRTTFO)
	}

	if !*noWarmup {
		_, body, err := measure(ctx, *target, px, modeRegular, *insecure, *timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warm-up request failed: %v\n", err)
			os.Exit(1)
		}
		if s := sample(body); s != "" {
			fmt.Printf("sample: %s\n", s)
		}
	}
	fmt.Println()

	runs := make(map[mode][]result, len(modes))
	for i := range *n {
		// Interleave the modes each iteration so none eats network warm-up bias.
		for _, m := range modes {
			pt, _, err := measure(ctx, *target, px, m, *insecure, *timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s run %d failed: %v\n", m, i+1, err)
				continue
			}
			runs[m] = append(runs[m], pt.result())
		}
	}

	var summary []namedResult
	for _, m := range modes {
		rs := runs[m]
		if len(rs) == 0 {
			fmt.Fprintf(os.Stderr, "no successful %s runs\n", m)
			continue
		}
		renderRuns(os.Stdout, fmt.Sprintf("%s (ms)", titleFor(m)), rs)
		fmt.Println()
		summary = append(summary, namedResult{m.String(), mean(rs)})
	}

	if len(summary) < 2 {
		fmt.Fprintln(os.Stderr, "not enough successful modes to compare")
		os.Exit(1)
	}
	renderComparison(os.Stdout, summary)
}

func titleFor(m mode) string {
	switch m {
	case modeRegular:
		return "Regular — sequential"
	case modePipelined:
		return "Pipelined — one write"
	case modeZeroRTT:
		return "0-RTT — handshake + first payload"
	case modeZeroRTTFO:
		return "0-RTT + TCP Fast Open"
	default:
		return m.String()
	}
}

func measure(ctx context.Context, target string, px *url.URL, m mode, insecure bool, timeout time.Duration) (*phaseTrace, []byte, error) {
	pt := &phaseTrace{}
	// Force HTTP/1.1 for clean, comparable trace semantics.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{
		DialContext:       makeDialContext(px, m, timeout, pt),
		DisableKeepAlives: true,
		Protocols:         protocols,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
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
		return nil, errors.New("missing SOCKS5 proxy URL argument")
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
	for line := range strings.SplitSeq(string(body), "\n") {
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

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func usage() {
	fmt.Fprint(os.Stderr, `socks5-pipelining-bench — compare SOCKS5 tunnel setup strategies

Measures regular, pipelined, and 0-rtt (and, with -tfo, 0-rtt+TCP Fast Open)
SOCKS5 CONNECT against a proxy, with a per-phase latency breakdown. The win
shows up in TTFB/TTLB and scales with the client->proxy RTT.

Usage:
  socks5-pipelining-bench [flags] socks5://[user:pass@]host:port

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\nExample:\n  socks5-pipelining-bench -n 5 -tfo socks5://user:pass@127.0.0.1:1080\n")
}
