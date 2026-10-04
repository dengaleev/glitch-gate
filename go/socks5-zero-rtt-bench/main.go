// Command bench measures SOCKS5 zero-RTT readiness of Go libraries: servers
// are checked in-process for pipelining (L1) and early data (L2), clients are
// timed over a netem topology (see run.sh) to count their round trips.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/clients"
	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/internal/s5"
	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/servers"
)

const usage = `bench — SOCKS5 zero-RTT readiness benchmark

  bench ready  [-v] [-pick FILE]         server L1/L2 checks (in-process)
  bench target -listen ADDR              TCP echo target
  bench proxy  -listen ADDR [-server NAME] [-user U -pass P]
  bench rtt    -proxy HOST -target ADDR [-n 30] [-c 8] [-rtts 0,20,80,200]
               [-show 80] [-dev IFACE] [-user U -pass P] [-payload 64]

Run "bench CMD -h" for flags; ./run.sh runs it all inside a netem topology.
`

func main() {
	cmds := map[string]func([]string) error{"ready": ready, "target": target, "proxy": proxy, "rtt": rtt}
	if len(os.Args) < 2 || cmds[os.Args[1]] == nil {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmds[os.Args[1]](os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "bench %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func ready(args []string) error {
	fs := flag.NewFlagSet("ready", flag.ExitOnError)
	verbose := fs.Bool("v", false, "print every failure, not just one detail per failed cell")
	pick := fs.String("pick", "", "also write the default proxy server's name (see bench proxy -server) to this file")
	_ = fs.Parse(args)

	reps := checkAll(context.Background())
	allocs := make([]string, len(servers.All))
	for i, s := range servers.All { // sequential: alloc counts are process-wide
		allocs[i] = fmtAllocs(servers.Allocs(s))
	}
	renderReady(os.Stdout, reps, allocs, *verbose)
	if *pick == "" {
		return nil
	}
	s, err := defaultServer(reps)
	if err != nil {
		return err
	}
	return os.WriteFile(*pick, []byte(s.Name+"\n"), 0o644)
}

func checkAll(ctx context.Context) []servers.Report {
	reps := make([]servers.Report, len(servers.All))
	var wg sync.WaitGroup
	for i, s := range servers.All {
		wg.Go(func() { reps[i] = servers.Check(ctx, s) })
	}
	wg.Wait()
	return reps
}

func target(args []string) error {
	fs := flag.NewFlagSet("target", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:7", "address to serve the TCP echo on")
	_ = fs.Parse(args)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	s5.Echo(ln)
	return nil
}

func proxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "address to serve SOCKS5 on")
	name := fs.String("server", "", "server implementation (default: the first that passes every readiness check)")
	user := fs.String("user", "", "require this username (empty: no auth)")
	pass := fs.String("pass", "", "password for -user")
	_ = fs.Parse(args)

	s, err := pickServer(*name)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "bench proxy: %s on %s (auth: %t)\n", s.Name, ln.Addr(), *user != "")
	return s.Serve(ln, *user, *pass)
}

// pickServer returns the named server or, by default, defaultServer.
func pickServer(name string) (servers.Server, error) {
	if name == "" {
		return defaultServer(checkAll(context.Background()))
	}
	for _, s := range servers.All {
		if strings.EqualFold(s.Name, name) {
			return s, nil
		}
	}
	return servers.Server{}, fmt.Errorf("unknown server %q (have: %s)", name, serverNames())
}

// defaultServer returns the first server whose report (reps[i], from
// checkAll) passes every readiness cell, so L2 clients get a proxy that
// keeps early data.
func defaultServer(reps []servers.Report) (servers.Server, error) {
	for i, r := range reps {
		if passesAll(r) {
			return servers.All[i], nil
		}
	}
	return servers.Server{}, errors.New("no server passes every readiness check; choose one with -server")
}

func passesAll(r servers.Report) bool {
	return len(r.Failures) == 0 && !slices.ContainsFunc(r.Cells, func(c servers.Cell) bool { return !c.OK })
}

func serverNames() string {
	names := make([]string, len(servers.All))
	for i, s := range servers.All {
		names[i] = s.Name
	}
	return strings.Join(names, ", ")
}

// authMode is one of the two proxies run.sh starts.
type authMode struct{ name, port, user, pass string }

// series is one client's cold dials in one auth mode, by RTT.
type series struct {
	byRTT map[int]latency // RTTs with at least one successful dial
	errs  []string
	dead  bool // every dial failed at some RTT: larger ones are skipped
}

type latency struct{ p50, p99 time.Duration }

func (s *series) record(rtt int, durs []time.Duration, errs []error) {
	if len(errs) > 0 {
		s.errs = append(s.errs, fmt.Sprintf("rtt %dms: %d/%d failed: %v", rtt, len(errs), len(durs)+len(errs), errs[0]))
	}
	if len(durs) == 0 {
		s.dead = true
		return
	}
	if s.byRTT == nil {
		s.byRTT = map[int]latency{}
	}
	slices.Sort(durs)
	s.byRTT[rtt] = latency{pct(durs, 50), pct(durs, 99)}
}

func rtt(args []string) error {
	fs := flag.NewFlagSet("rtt", flag.ExitOnError)
	proxyHost := fs.String("proxy", "127.0.0.1", "proxy host: no-auth on :1080, user/pass on :1081")
	targetAddr := fs.String("target", "127.0.0.1:7", "echo target address, as seen from the proxy")
	n := fs.Int("n", 30, "cold dials per client, auth mode and RTT")
	conc := fs.Int("c", 8, "concurrent dials")
	grid := fs.String("rtts", "0,20,80,200", "client↔proxy RTTs to emulate, ms")
	show := fs.Int("show", 80, "RTT (ms) whose p50/p99 are shown")
	dev := fs.String("dev", "", "interface to put the netem delay on (empty: don't touch the network)")
	user := fs.String("user", "bench", "username for the user/pass proxy")
	pass := fs.String("pass", "bench", "password for the user/pass proxy")
	size := fs.Int("payload", 64, "bytes written and echoed per dial")
	timeout := fs.Duration("timeout", 10*time.Second, "per-dial timeout")
	serverName := fs.String("server", "", "proxy implementation, for the title only")
	ptRTT := fs.Int("pt-rtt", -1, "proxy↔target RTT in ms, for the title only")
	_ = fs.Parse(args)

	rtts, err := parseRTTs(*grid)
	if err != nil {
		return err
	}
	if *dev == "" {
		fmt.Fprintln(os.Stderr, "bench rtt: no -dev, measuring the network as is")
	}
	modes := []authMode{{"none", "1080", "", ""}, {"u/p", "1081", *user, *pass}}
	sw := sweep{
		proxyHost: *proxyHost, target: *targetAddr, payload: bytes.Repeat([]byte{'x'}, *size),
		n: *n, conc: *conc, timeout: *timeout,
	}
	ctx := context.Background()
	res, err := sw.run(ctx, *dev, rtts, modes)
	if err != nil {
		return err
	}

	showRTT := *show
	if !slices.Contains(rtts, showRTT) {
		showRTT = slices.Max(rtts)
	}
	renderClients(os.Stdout, clientsView{
		rows: probeClients(ctx, res), modes: modes, rtts: rtts, show: showRTT,
		n: *n, conc: *conc, payload: *size, ptRTT: *ptRTT, server: *serverName,
	})
	return nil
}

// sweep is the cold-dial setup shared by every client, auth mode and RTT.
type sweep struct {
	proxyHost, target string
	payload           []byte
	n, conc           int
	timeout           time.Duration
}

// run dials every client in every mode at each RTT (set on dev) and returns
// res[client][mode].
func (sw sweep) run(ctx context.Context, dev string, rtts []int, modes []authMode) ([][]series, error) {
	res := make([][]series, len(clients.All))
	for i := range res {
		res[i] = make([]series, len(modes))
	}
	for _, r := range rtts {
		if err := setDelay(dev, r); err != nil {
			return nil, err
		}
		for i, c := range clients.All {
			for m, mode := range modes {
				if s := &res[i][m]; !s.dead {
					progress("rtt %dms  %s (%s)", r, c.Name, mode.name)
					durs, errs := sw.dials(ctx, c, mode)
					s.record(r, durs, errs)
				}
			}
		}
	}
	_ = setDelay(dev, 0)
	return res, nil
}

// dials runs sw.n cold dials, sw.conc at a time.
func (sw sweep) dials(ctx context.Context, c clients.Client, mode authMode) ([]time.Duration, []error) {
	proxy := net.JoinHostPort(sw.proxyHost, mode.port)
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		durs []time.Duration
		errs []error
		sem  = make(chan struct{}, max(sw.conc, 1))
	)
	for range sw.n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(ctx, sw.timeout)
			defer cancel()
			d, err := clients.Once(ctx, c, proxy, mode.user, mode.pass, sw.target, sw.payload)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			} else {
				durs = append(durs, d)
			}
		})
	}
	wg.Wait()
	return durs, errs
}

// probeClients runs the in-process probes; call it after the sweep, since
// alloc counts are process-wide.
func probeClients(ctx context.Context, res [][]series) []clientRow {
	rows := make([]clientRow, len(clients.All))
	for i, c := range clients.All {
		progress("probing %s", c.Name)
		l2, err := clients.EarlyData(ctx, c, "", "")
		rows[i] = clientRow{name: c.Name, l2: l2, l2err: err, allocs: fmtAllocs(clients.Allocs(c, "", "")), res: res[i]}
	}
	progress("")
	return rows
}

// setDelay puts the whole emulated RTT on dev's egress; no-op without dev.
func setDelay(dev string, ms int) error {
	if dev == "" {
		return nil
	}
	out, err := exec.Command("tc", "qdisc", "replace", "dev", dev, "root", "netem", "delay", fmt.Sprintf("%dms", ms)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc netem on %s: %v: %s", dev, err, bytes.TrimSpace(out))
	}
	return nil
}

// parseRTTs parses a comma-separated ms list, sorted and deduplicated.
func parseRTTs(s string) ([]int, error) {
	var rtts []int
	for f := range strings.SplitSeq(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || v < 0 {
			return nil, fmt.Errorf("bad -rtts entry %q", f)
		}
		rtts = append(rtts, v)
	}
	slices.Sort(rtts)
	return slices.Compact(rtts), nil
}

// pct is the nearest-rank percentile of sorted durations.
func pct(sorted []time.Duration, p int) time.Duration {
	return sorted[max((len(sorted)*p+99)/100-1, 0)]
}

var stderrIsTTY = func() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

// progress rewrites one status line on a terminal stderr.
func progress(format string, a ...any) {
	if stderrIsTTY {
		fmt.Fprintf(os.Stderr, "\r\033[K"+format, a...)
	}
}
