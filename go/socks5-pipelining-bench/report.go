package main

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

// phaseTrace holds the absolute timestamps captured during one request, both
// from the custom dialer (DNS/TCP/SOCKS5) and from httptrace (TLS/first byte).
type phaseTrace struct {
	start               time.Time // request issued
	dnsStart, dnsDone   time.Time // proxy hostname resolution (skipped if proxy is an IP)
	connStart, connDone time.Time // TCP connect to the proxy
	socksDone           time.Time // SOCKS5 handshake complete (socksStart == connDone)
	tlsStart, tlsDone   time.Time // TLS handshake to the target (https only)
	firstByte           time.Time // first response byte (TTFB)
	done                time.Time // response body fully read (TTLB)
}

// result is the per-phase duration breakdown derived from a phaseTrace.
// The optional phases (dns, tls) are left zero when they did not occur — a
// measured timestamp delta is always > 0, so zero unambiguously means "absent".
type result struct {
	dns   time.Duration // proxy DNS lookup (0 if proxy is an IP)
	tcp   time.Duration // TCP connect to proxy
	socks time.Duration // SOCKS5 handshake
	tls   time.Duration // TLS handshake to target (0 for http)
	wait  time.Duration // server processing: ready -> first byte
	ttfb  time.Duration // request start -> first byte
	ttlb  time.Duration // request start -> last byte (total)
}

func (pt *phaseTrace) result() result {
	var r result
	if !pt.dnsStart.IsZero() {
		r.dns = pt.dnsDone.Sub(pt.dnsStart)
	}
	r.tcp = pt.connDone.Sub(pt.connStart)
	r.socks = pt.socksDone.Sub(pt.connDone)

	ready := pt.socksDone
	if !pt.tlsStart.IsZero() {
		r.tls = pt.tlsDone.Sub(pt.tlsStart)
		ready = pt.tlsDone
	}
	if !pt.firstByte.IsZero() {
		r.wait = pt.firstByte.Sub(ready)
		r.ttfb = pt.firstByte.Sub(pt.start)
	}
	r.ttlb = pt.done.Sub(pt.start)
	return r
}

func mean(rs []result) result {
	var m result
	if len(rs) == 0 {
		return m
	}
	for _, r := range rs {
		m.dns += r.dns
		m.tcp += r.tcp
		m.socks += r.socks
		m.tls += r.tls
		m.wait += r.wait
		m.ttfb += r.ttfb
		m.ttlb += r.ttlb
	}
	n := time.Duration(len(rs))
	m.dns /= n
	m.tcp /= n
	m.socks /= n
	m.tls /= n
	m.wait /= n
	m.ttfb /= n
	m.ttlb /= n
	return m
}

func ms(d time.Duration) string { return fmt.Sprintf("%.2f", float64(d)/float64(time.Millisecond)) }

// cell renders an optional phase: "-" when it did not occur (zero), else ms.
func cell(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return ms(d)
}

func renderRuns(w io.Writer, title string, rs []result) {
	fmt.Fprintf(w, "%s\n", title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "run\tDNS\tTCP\tSOCKS5\tTLS\tWait\tTTFB\tTTLB\t")
	for i, r := range rs {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			i+1, cell(r.dns), ms(r.tcp), ms(r.socks),
			cell(r.tls), ms(r.wait), ms(r.ttfb), ms(r.ttlb))
	}
	m := mean(rs)
	fmt.Fprintf(tw, "avg\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
		cell(m.dns), ms(m.tcp), ms(m.socks),
		cell(m.tls), ms(m.wait), ms(m.ttfb), ms(m.ttlb))
	_ = tw.Flush()
	fmt.Fprintln(w)
}

func renderComparison(w io.Writer, reg, pip result) {
	fmt.Fprintln(w, "Comparison (averages)")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "phase\tregular\tpipelined\tdelta\tdelta%\t")
	row := func(name string, a, b time.Duration, has bool) {
		if !has {
			fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t\n", name)
			return
		}
		delta := b - a
		pct := 0.0
		if a != 0 {
			pct = float64(delta) / float64(a) * 100
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%+.2f\t%+.1f%%\t\n",
			name, ms(a), ms(b), float64(delta)/float64(time.Millisecond), pct)
	}
	row("DNS", reg.dns, pip.dns, reg.dns != 0)
	row("TCP", reg.tcp, pip.tcp, true)
	row("SOCKS5", reg.socks, pip.socks, true)
	row("TLS", reg.tls, pip.tls, reg.tls != 0)
	row("Wait", reg.wait, pip.wait, true)
	row("TTFB", reg.ttfb, pip.ttfb, true)
	row("TTLB", reg.ttlb, pip.ttlb, true)
	_ = tw.Flush()
}
