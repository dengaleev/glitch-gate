package main

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/servers"
)

// newTable returns a light-style table, right-aligned from column rightFrom
// (1-based) on.
func newTable(w io.Writer, title string, header table.Row, rightFrom int) table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetTitle(title)
	style := table.StyleLight
	style.Format.Header = text.FormatDefault
	t.SetStyle(style)
	var cfgs []table.ColumnConfig
	for i := rightFrom; i <= len(header); i++ {
		cfgs = append(cfgs, table.ColumnConfig{Number: i, Align: text.AlignRight, AlignHeader: text.AlignRight})
	}
	t.SetColumnConfigs(cfgs)
	t.AppendHeader(header)
	return t
}

func fmtAllocs(v float64, err error) string {
	if err != nil {
		return "err"
	}
	return fmt.Sprintf("%.0f", v)
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f", float64(d)/float64(time.Millisecond)) }

func mark(ok bool) string {
	if ok {
		return "✅"
	}
	return "❌"
}

// renderReady prints the server readiness matrix, then every failure
// (verbose) or one detail per failed cell.
func renderReady(w io.Writer, reps []servers.Report, allocs []string, verbose bool) {
	header := table.Row{"server"}
	for _, c := range servers.Columns {
		header = append(header, c)
	}
	t := newTable(w, "Servers · L1/L2 readiness (in-process)", append(header, "allocs/op"), len(header)+1)
	var notes []string
	for i, r := range reps {
		row := table.Row{r.Server}
		for j, c := range r.Cells {
			switch {
			case c.Skipped:
				row = append(row, "–")
			case c.OK:
				row = append(row, mark(true))
			default:
				row = append(row, strings.TrimSpace(mark(false)+" "+c.Reason))
				if c.Detail != "" && !verbose {
					notes = append(notes, fmt.Sprintf("%s · %s: %s", r.Server, column(j), strings.TrimPrefix(c.Detail, column(j)+" ")))
				}
			}
		}
		t.AppendRow(append(row, allocs[i]))
		if verbose {
			for _, f := range r.Failures {
				notes = append(notes, r.Server+": "+f)
			}
		}
	}
	t.Render()
	for _, n := range notes {
		fmt.Fprintln(w, "  "+n)
	}
}

func column(i int) string {
	if i < len(servers.Columns) {
		return servers.Columns[i]
	}
	return strconv.Itoa(i + 1)
}

// clientRow is one client's sweep results plus its in-process probes.
type clientRow struct {
	name   string
	l2     bool
	l2err  error
	allocs string
	res    []series // indexed like clientsView.modes
}

type clientsView struct {
	rows                    []clientRow
	modes                   []authMode
	rtts                    []int // ascending
	show                    int   // RTT whose p50/p99 are shown
	n, conc, payload, ptRTT int
	server                  string
}

func (v clientsView) title() string {
	t := "Clients · cold dial via netem"
	if v.server != "" {
		t += " · proxy: " + v.server
	}
	t += fmt.Sprintf("\nn=%d c=%d · client↔proxy RTT %s ms", v.n, v.conc, joinInts(v.rtts))
	if v.ptRTT >= 0 {
		t += fmt.Sprintf(" · proxy↔target %d ms", v.ptRTT)
	}
	return t + fmt.Sprintf(" · %d B", v.payload)
}

// renderClients prints per client: round trips per auth mode, no-auth
// latency at the shown RTT, and the in-process probes.
func renderClients(w io.Writer, v clientsView) {
	lo, hi := v.rtts[0], v.rtts[len(v.rtts)-1]
	header := table.Row{"client", "L2"}
	for _, m := range v.modes {
		header = append(header, "RTTs "+m.name)
	}
	tail := "p99"
	if v.n < 100 { // nearest-rank p99 of <100 dials is the max
		tail = "max"
	}
	t := newTable(w, v.title(), append(header, "p50 ms", tail+" ms", "allocs/op"), 3)

	var errs []string
	for _, r := range v.rows {
		l2 := mark(r.l2)
		if r.l2err != nil {
			l2 = "err"
			errs = append(errs, fmt.Sprintf("%s · L2 probe: %v", r.name, r.l2err))
		}
		row := table.Row{r.name, l2}
		for m, s := range r.res {
			row = append(row, roundTrips(s, lo, hi))
			for _, e := range s.errs {
				errs = append(errs, fmt.Sprintf("%s · %s · %s", r.name, v.modes[m].name, e))
			}
		}
		p50, p99 := "err", "err"
		if l, ok := r.res[0].byRTT[v.show]; ok {
			p50, p99 = ms(l.p50), ms(l.p99)
		}
		t.AppendRow(append(row, p50, p99, r.allocs))
	}
	t.Render()

	fmt.Fprintf(w, "  RTTs: client↔proxy round trips to the echo incl. TCP handshake, (p50@%d − p50@%d) / %d ms;\n", hi, lo, hi-lo)
	fmt.Fprintln(w, "        expect sequential 4 (none) / 5 (u/p), L1 3, L1+L2 2. * = some dials failed.")
	fmt.Fprintf(w, "  p50/"+tail+": no-auth at %d ms RTT. L2, allocs/op: in-process, no-auth.\n", v.show)
	for _, e := range errs {
		fmt.Fprintln(w, "  "+e)
	}
}

// roundTrips estimates client↔proxy round trips per dial from the p50 slope
// between RTTs lo and hi; one decimal if it is >0.25 off an integer.
func roundTrips(s series, lo, hi int) string {
	a, okA := s.byRTT[lo]
	b, okB := s.byRTT[hi]
	switch {
	case !okA || !okB:
		return "err"
	case hi == lo:
		return "?"
	}
	est := float64(b.p50-a.p50) / float64(time.Duration(hi-lo)*time.Millisecond)
	out := strconv.Itoa(int(math.Round(est)))
	if math.Abs(est-math.Round(est)) > 0.25 {
		out = fmt.Sprintf("%.1f", est)
	}
	if len(s.errs) > 0 {
		out += "*"
	}
	return out
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ",")
}
