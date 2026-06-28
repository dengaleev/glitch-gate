package main

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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
	for _, r := range rs {
		m.dns += r.dns
		m.tcp += r.tcp
		m.socks += r.socks
		m.tls += r.tls
		m.wait += r.wait
		m.ttfb += r.ttfb
		m.ttlb += r.ttlb
	}
	if n := time.Duration(len(rs)); n > 0 {
		m.dns /= n
		m.tcp /= n
		m.socks /= n
		m.tls /= n
		m.wait /= n
		m.ttfb /= n
		m.ttlb /= n
	}
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

var phaseHeader = table.Row{"run", "DNS", "TCP", "SOCKS5", "TLS", "Wait", "TTFB", "TTLB"}

// newTable builds a styled table with every column right-aligned except the
// first (the label column).
func newTable(w io.Writer, title string, cols int) table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetTitle(title)
	t.SetStyle(table.StyleLight)
	cfgs := make([]table.ColumnConfig, 0, cols-1)
	for i := 2; i <= cols; i++ {
		cfgs = append(cfgs, table.ColumnConfig{
			Number:      i,
			Align:       text.AlignRight,
			AlignHeader: text.AlignRight,
			AlignFooter: text.AlignRight,
		})
	}
	t.SetColumnConfigs(cfgs)
	return t
}

func runRow(label string, r result) table.Row {
	return table.Row{label, cell(r.dns), ms(r.tcp), ms(r.socks), cell(r.tls), ms(r.wait), ms(r.ttfb), ms(r.ttlb)}
}

func renderRuns(w io.Writer, title string, rs []result) {
	t := newTable(w, title, len(phaseHeader))
	t.AppendHeader(phaseHeader)
	for i, r := range rs {
		t.AppendRow(runRow(strconv.Itoa(i+1), r))
	}
	t.AppendFooter(runRow("avg", mean(rs)))
	t.Render()
}

func renderComparison(w io.Writer, reg, pip result) {
	t := newTable(w, "Comparison — averages (ms)", 5)
	t.AppendHeader(table.Row{"phase", "regular", "pipelined", "Δ", "Δ%"})
	row := func(name string, a, b time.Duration, optional bool) {
		if optional && (a == 0 || b == 0) {
			t.AppendRow(table.Row{name, "-", "-", "-", "-"})
			return
		}
		delta := b - a
		pct := 0.0
		if a != 0 {
			pct = float64(delta) / float64(a) * 100
		}
		t.AppendRow(table.Row{name, ms(a), ms(b),
			fmt.Sprintf("%+.2f", float64(delta)/float64(time.Millisecond)),
			fmt.Sprintf("%+.1f%%", pct)})
	}
	row("DNS", reg.dns, pip.dns, true)
	row("TCP", reg.tcp, pip.tcp, false)
	row("SOCKS5", reg.socks, pip.socks, false)
	row("TLS", reg.tls, pip.tls, true)
	row("Wait", reg.wait, pip.wait, false)
	row("TTFB", reg.ttfb, pip.ttfb, false)
	row("TTLB", reg.ttlb, pip.ttlb, false)
	t.Render()
}
