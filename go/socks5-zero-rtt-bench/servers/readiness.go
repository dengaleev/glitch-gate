package servers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/internal/s5"
)

// Columns of the readiness table, in order.
var Columns = []string{"L1", "L2·64B", "L2·1.5K", "L2·64K", "split"}

// Cell is one aggregated table cell.
type Cell struct {
	OK      bool
	Skipped bool   // no case ran
	Reason  string // distinct failure tags ("lost", "trunc", "hang", ...) joined by "/"
	Detail  string // first failing case and its error
}

// Report is one server's row of the readiness table.
type Report struct {
	Server   string
	Cells    []Cell   // aligned with Columns
	Failures []string // every failing case, one per line
}

const (
	caseTimeout = 3 * time.Second
	segGap      = 1500 * time.Microsecond // with TCP_NODELAY, each write is its own segment
	finGrace    = 100 * time.Millisecond
	parallel    = 32
)

// sizes[i] is the early-data size of Columns[i]; the split column follows.
var sizes = [...]int{0, 64, 1536, 64 << 10}

const splitCol = len(sizes)

// probe is sent only after the CONNECT reply, so a live tunnel always echoes
// it: that tells lost early data from a hang. For L1 it is the whole echo.
var probe = []byte("\x00post-reply probe\xff")

// payload is deterministic and non-repeating, so loss or reorder shows.
var payload = sync.OnceValue(func() []byte {
	b := make([]byte, slices.Max(sizes[:]))
	_, _ = rand.NewChaCha8([32]byte{'s', 'o', 'c', 'k', 's', '5'}).Read(b)
	return b
})

var hasIPv6 = sync.OnceValue(func() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err == nil {
		ln.Close()
	}
	return err == nil
})

// kase is one case of the matrix.
type kase struct {
	col        int
	user, pass string
	host       string // picks the ATYP
	size       int    // early-data bytes
	split      int    // index into splits
}

func (k kase) String() string {
	auth := "noauth"
	if k.user != "" {
		auth = "userpass"
	}
	return fmt.Sprintf("%s %s %s %dB %s", Columns[k.col], auth, k.host, k.size, splits[k.split].name)
}

func matrix(userPass bool) []kase {
	auths := [][2]string{{"", ""}}
	if userPass {
		auths = append(auths, [2]string{"user", "pass"})
	}
	hosts := []string{"127.0.0.1", "localhost"}
	if hasIPv6() {
		hosts = append(hosts, "::1")
	}
	var ks []kase
	for _, a := range auths {
		for _, h := range hosts {
			for col, size := range sizes {
				ks = append(ks, kase{col, a[0], a[1], h, size, oneWrite})
				for sp := oneWrite + 1; sp < len(splits); sp++ {
					ks = append(ks, kase{splitCol, a[0], a[1], h, size, sp})
				}
			}
		}
	}
	return ks
}

// message is what a zero-RTT client writes: greeting, [auth], CONNECT, early data.
type message struct {
	wire      []byte
	hsLen     int   // handshake bytes; the rest of wire is early data
	partEnds  []int // end offset of each part
	fieldLens []int // every protocol field, in order
}

func newMessage(user, pass, target string, early []byte) (message, error) {
	req, err := s5.Connect(target)
	if err != nil {
		return message{}, err
	}
	parts := [][]byte{s5.Greeting(user)}
	fields := []int{1, 1, 1} // VER NMETHODS METHODS
	if user != "" {
		parts = append(parts, s5.Auth(user, pass))
		fields = append(fields, 1, 1, len(user), 1, len(pass))
	}
	parts = append(parts, req)
	fields = append(fields, 1, 1, 1, 1) // VER CMD RSV ATYP
	switch atyp := req[3]; atyp {
	case 1:
		fields = append(fields, net.IPv4len)
	case 4:
		fields = append(fields, net.IPv6len)
	default: // domain
		fields = append(fields, 1, int(req[4]))
	}
	fields = append(fields, 2) // port
	if len(early) > 0 {
		parts = append(parts, early)
		fields = append(fields, len(early))
	}
	m := message{wire: slices.Concat(parts...), fieldLens: fields}
	end := 0
	for _, p := range parts {
		end += len(p)
		m.partEnds = append(m.partEnds, end)
	}
	m.hsLen = len(m.wire) - len(early)
	return m, nil
}

func (m message) early() []byte { return m.wire[m.hsLen:] }

// segments cuts m.wire at cuts, but never at hsLen: the last handshake byte
// must travel with the early data, or the server finishes the handshake
// during the gap and the data is no longer early.
func (m message) segments(cuts []int) [][]byte {
	slices.Sort(cuts)
	var segs [][]byte
	last := 0
	for _, c := range slices.Compact(cuts) {
		if c > last && c < len(m.wire) && c != m.hsLen {
			segs = append(segs, m.wire[last:c])
			last = c
		}
	}
	return append(segs, m.wire[last:])
}

const oneWrite = 0 // index into splits

// splits are the write patterns; all but oneWrite make up the split column.
var splits = []struct {
	name string
	cuts func(message) []int
}{
	oneWrite: {"one", func(message) []int { return nil }},
	{"hs-bytes", func(m message) []int { // early data stays one write
		var cs []int
		for i := range m.hsLen {
			cs = append(cs, i+1)
		}
		return cs
	}},
	{"boundaries", func(m message) []int { return slices.Clone(m.partEnds) }},
	{"mid-field", func(m message) []int {
		var cs []int
		off := 0
		for _, n := range m.fieldLens {
			cs = append(cs, off+max(1, n/2))
			off += n
		}
		return cs
	}},
	{"rand1", randCuts(1)},
	{"rand2", randCuts(2)},
	{"rand3", randCuts(3)},
}

// randCuts makes 1-19 reproducible cuts near the handshake end, where they matter.
func randCuts(seed uint64) func(message) []int {
	return func(m message) []int {
		r := rand.New(rand.NewPCG(seed, uint64(len(m.wire))))
		span := min(len(m.wire), m.hsLen+128)
		var cs []int
		for range 1 + r.IntN(19) {
			cs = append(cs, 1+r.IntN(span-1))
		}
		return cs
	}
}

// failure is a case failure tagged with a reason.
type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func failf(reason, format string, args ...any) error {
	return &failure{reason, fmt.Errorf(format, args...)}
}

func reasonOf(err error) string {
	if f, ok := errors.AsType[*failure](err); ok {
		return f.reason
	}
	return "error"
}

func netReason(err error, otherwise string) string {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "hang"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return "closed"
	}
	return otherwise
}

// rig is a running server under test plus a fresh echo target.
type rig struct {
	proxy     string
	target    string // host:port as the client names it
	listeners []net.Listener
	noFIN     atomic.Bool // see hangUp
}

func startRig(s Server, user, pass, host string) (*rig, error) {
	lns, port, err := echoListeners(host)
	if err != nil {
		return nil, err
	}
	for _, ln := range lns {
		go echo(ln)
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeAll(lns)
		return nil, err
	}
	go func() {
		_ = s.Serve(proxyLn, user, pass)
		proxyLn.Close() // a failed Serve refuses dials instead of hanging them
	}()
	return &rig{
		proxy:     proxyLn.Addr().String(),
		target:    net.JoinHostPort(host, port),
		listeners: append(lns, proxyLn),
	}, nil
}

func (r *rig) close() { closeAll(r.listeners) }

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		ln.Close()
	}
}

// echo is s5.Echo, but hangs up once the probe is echoed: the target
// closing first keeps TIME_WAIT off the server's ephemeral ports.
func echo(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 32<<10)
			for {
				n, err := c.Read(buf)
				if _, werr := c.Write(buf[:n]); werr != nil || err != nil || bytes.HasSuffix(buf[:n], probe) {
					return
				}
			}
		}()
	}
}

// hangUp closes c without leaving TIME_WAIT on its port (tight benchmark
// loops would exhaust them) and without sending the server down an error
// path: it waits for the target's FIN relayed by the server and closes
// second. A server that doesn't relay it is learned once and gets RSTs.
func (r *rig) hangUp(c net.Conn) {
	if !r.noFIN.Load() {
		var b [1]byte
		_ = c.SetReadDeadline(time.Now().Add(finGrace))
		if _, err := c.Read(b[:]); errors.Is(err, io.EOF) {
			c.Close()
			return
		}
		r.noFIN.Store(true)
	}
	closeRST(c)
}

// closeRST closes c with an RST, which skips TIME_WAIT.
func closeRST(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
}

// echoListeners listens on host; for localhost on both 127.0.0.1 and ::1 at
// one port, whichever the server resolves.
func echoListeners(host string) ([]net.Listener, string, error) {
	ips := []string{host}
	if host == "localhost" {
		ips = []string{"127.0.0.1"}
		if hasIPv6() {
			ips = append(ips, "::1")
		}
	}
	for range 100 { // the port may be taken on the second IP
		var lns []net.Listener
		port := "0"
		for _, ip := range ips {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
			if err != nil {
				break
			}
			lns = append(lns, ln)
			_, port, _ = net.SplitHostPort(ln.Addr().String())
		}
		if len(lns) == len(ips) {
			return lns, port, nil
		}
		closeAll(lns)
	}
	return nil, "", fmt.Errorf("no common free port for %v", ips)
}

// run makes one zero-RTT tunnel as k says and verifies the echo.
func (r *rig) run(ctx context.Context, k kase) error {
	m, err := newMessage(k.user, k.pass, r.target, payload()[:k.size])
	if err != nil {
		return &failure{"setup", err}
	}
	segs := m.segments(splits[k.split].cuts(m))
	got, err := r.exchange(ctx, k.user, segs, len(m.early())+len(probe))
	if _, classified := errors.AsType[*failure](err); classified {
		return err
	}
	return verify(m.early(), got, err)
}

// exchange writes segs without waiting for replies, reads the replies, sends
// the probe, and reads the echo until want bytes or the probe. Writes run
// concurrently with reads, so large early data can't deadlock.
func (r *rig) exchange(ctx context.Context, user string, segs [][]byte, want int) (got []byte, err error) {
	c, err := new(net.Dialer).DialContext(ctx, "tcp", r.proxy)
	if err != nil {
		return nil, &failure{"setup", err}
	}
	defer func() {
		if err == nil {
			r.hangUp(c)
		} else {
			closeRST(c)
		}
	}()
	_ = c.SetDeadline(time.Now().Add(caseTimeout))

	replied, done := make(chan struct{}), make(chan struct{})
	defer close(done)
	go func() {
		for i, seg := range segs {
			if i > 0 {
				time.Sleep(segGap)
			}
			if _, err := c.Write(seg); err != nil {
				return
			}
		}
		select {
		case <-replied:
			_, _ = c.Write(probe)
		case <-done:
		}
	}()

	if err := s5.ReadReplies(c, user); err != nil {
		return nil, &failure{netReason(err, "reject"), err}
	}
	close(replied)
	got = make([]byte, 0, want)
	for len(got) < want && !bytes.HasSuffix(got, probe) {
		n, err := c.Read(got[len(got):cap(got)])
		got = got[:len(got)+n]
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// verify compares the echo with early+probe and names what went wrong.
func verify(early, got []byte, err error) error {
	want := slices.Concat(early, probe)
	if bytes.Equal(got, want) {
		return nil
	}
	if body, probed := bytes.CutSuffix(got, probe); probed {
		switch {
		case len(body) == 0:
			return failf("lost", "none of %d early bytes reached the target", len(early))
		case bytes.HasSuffix(early, body):
			return failf("lost", "first %d of %d early bytes never reached the target", len(early)-len(body), len(early))
		case bytes.HasPrefix(early, body):
			return failf("trunc", "only the first %d of %d early bytes reached the target", len(body), len(early))
		}
		return failf("garbled", "early data came back altered (%d bytes for %d sent)", len(body), len(early))
	}
	if bytes.HasPrefix(want, got) {
		return &failure{netReason(err, "closed"), fmt.Errorf("echo stopped at %d of %d bytes: %w", len(got), len(want), err)}
	}
	return failf("garbled", "echo differs from what was sent (%d bytes, want %d)", len(got), len(want))
}

// Check runs the readiness matrix against s, in-process on loopback.
func Check(ctx context.Context, s Server) Report {
	ks := matrix(s.UserPass)
	errs := runCases(ctx, s, ks)

	rep := Report{Server: s.Name, Cells: make([]Cell, len(Columns))}
	ran := make([]bool, len(Columns))
	reasons := make([][]string, len(Columns))
	for i, k := range ks {
		ran[k.col] = true
		if errs[i] == nil {
			continue
		}
		line := fmt.Sprintf("%v: %v", k, errs[i])
		rep.Failures = append(rep.Failures, line)
		if r := reasonOf(errs[i]); !slices.Contains(reasons[k.col], r) {
			reasons[k.col] = append(reasons[k.col], r)
		}
		if rep.Cells[k.col].Detail == "" {
			rep.Cells[k.col].Detail = line
		}
	}
	for i := range rep.Cells {
		c := &rep.Cells[i]
		c.Skipped = !ran[i]
		c.OK = ran[i] && len(reasons[i]) == 0
		c.Reason = strings.Join(reasons[i], "/")
	}
	return rep
}

// runCases runs ks, at most parallel at a time; errs[i] belongs to ks[i].
func runCases(ctx context.Context, s Server, ks []kase) []error {
	errs := make([]error, len(ks))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, k := range ks {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				errs[i] = checkCase(ctx, s, k)
			case <-ctx.Done():
				errs[i] = &failure{"canceled", ctx.Err()}
			}
		})
	}
	wg.Wait()
	return errs
}

func checkCase(ctx context.Context, s Server, k kase) error {
	r, err := startRig(s, k.user, k.pass, k.host)
	if err != nil {
		return &failure{"setup", err}
	}
	defer r.close()
	return r.run(ctx, k)
}

// allocCase is the Allocs/benchmark unit: no-auth IPv4, one-write handshake,
// probe-only echo. It needs only L1, so every server can be measured.
var allocCase = kase{col: 0, host: "127.0.0.1", split: oneWrite}

// Allocs reports heap allocations, all goroutines included, per pipelined
// dial + small echo through s. About 35 of them are the harness's (client,
// echo target, dial/accept), the same for every server; a minimal
// io.ReadFull server totals ~95.
func Allocs(s Server) (float64, error) {
	r, err := allocRig(s)
	if err != nil {
		return 0, err
	}
	defer r.close()
	var firstErr error
	n := testing.AllocsPerRun(100, func() {
		if err := r.run(context.Background(), allocCase); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return n, firstErr
}

// allocRig starts a rig for allocCase and runs it once: to warm up, to let
// hangUp learn the server's close behavior, and to fail early if broken.
func allocRig(s Server) (*rig, error) {
	r, err := startRig(s, "", "", allocCase.host)
	if err != nil {
		return nil, err
	}
	if err := r.run(context.Background(), allocCase); err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}
