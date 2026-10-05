package server_test

// The readiness matrix of ../socks5-zero-rtt-bench, ported, plus extra cells: early data sent with
// the handshake, in any segmentation, reaches the target exactly once.

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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var columns = []string{"L1", "L2·64B", "L2·1.5K", "L2·64K", "split"}

const (
	caseTimeout = 5 * time.Second
	segGap      = 1500 * time.Microsecond // with TCP_NODELAY, each write is its own segment
	finGrace    = 100 * time.Millisecond
	parallel    = 32
)

// Early-data size per column; the split column follows.
var sizes = [...]int{0, 64, 1536, 64 << 10}

const splitCol = len(sizes)

// probe, sent after the reply, tells lost early data from a hang.
var probe = []byte("\x00post-reply probe\xff")

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
	return fmt.Sprintf("%s %s %s %dB %s", columns[k.col], auth, k.host, k.size, splits[k.split].name)
}

func matrix() []kase {
	hosts := []string{"127.0.0.1", "localhost"}
	if hasIPv6() {
		hosts = append(hosts, "::1")
	}
	var ks []kase
	for _, a := range [][2]string{{"", ""}, {"user", "pass"}} {
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

// message is greeting, [auth], CONNECT, early data, as one zero-RTT write.
type message struct {
	wire      []byte
	hsLen     int // handshake bytes; the rest of wire is early data
	partEnds  []int
	fieldLens []int // every protocol field, in order
}

func newMessage(user, pass, target string, early []byte) message {
	req := request(wire.CmdConnect, target)
	parts := [][]byte{greeting(wire.MethodNoAuth)}
	fields := []int{1, 1, 1}
	if user != "" {
		parts = [][]byte{greeting(wire.MethodUserPass), userPass(user, pass)}
		fields = append(fields, 1, 1, len(user), 1, len(pass))
	}
	parts = append(parts, req)
	fields = append(fields, 1, 1, 1, 1)
	switch req[3] {
	case 1:
		fields = append(fields, net.IPv4len)
	case 4:
		fields = append(fields, net.IPv6len)
	default:
		fields = append(fields, 1, int(req[4]))
	}
	fields = append(fields, 2)
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
	return m
}

func (m message) early() []byte { return m.wire[m.hsLen:] }

// segments never cuts at hsLen, or the data would no longer be early.
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

// Write patterns; all but oneWrite make up the split column.
var splits = []struct {
	name string
	cuts func(message) []int
}{
	oneWrite: {"one", func(message) []int { return nil }},
	{"hs-bytes", func(m message) []int {
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

// randCuts makes 1-19 seeded cuts near the handshake end.
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

type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func failf(reason, format string, args ...any) error {
	return &failure{reason, fmt.Errorf(format, args...)}
}

func netReason(err error, otherwise string) string {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "hang"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), isReset(err):
		return "closed"
	}
	return otherwise
}

type rig struct {
	srv       *server.Server
	proxy     string
	target    string
	listeners []net.Listener
	wg        sync.WaitGroup
	noFIN     atomic.Bool
}

// startRig serves s, or with serve another server, in front of an echo target on host.
func startRig(s *server.Server, host string, serve func(net.Listener)) (*rig, error) {
	r := &rig{srv: s}
	if serve == nil {
		serve = func(ln net.Listener) { _ = s.Serve(ln) }
	}
	lns, port, err := echoListeners(host)
	if err != nil {
		return nil, err
	}
	for _, ln := range lns {
		r.wg.Go(func() { r.echo(ln) })
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeAll(lns)
		return nil, err
	}
	r.wg.Go(func() { serve(proxyLn) })
	r.proxy = proxyLn.Addr().String()
	r.target = net.JoinHostPort(host, port)
	r.listeners = append(lns, proxyLn)
	return r, nil
}

func (r *rig) close() {
	closeAll(r.listeners)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.srv.Shutdown(ctx)
	r.srv.Close()
	r.wg.Wait()
}

// echo hangs up first, keeping TIME_WAIT off the server's ephemeral ports.
func (r *rig) echo(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r.wg.Go(func() {
			defer c.Close()
			buf := make([]byte, 32<<10)
			for {
				n, err := c.Read(buf)
				if _, werr := c.Write(buf[:n]); werr != nil || err != nil || bytes.HasSuffix(buf[:n], probe) {
					return
				}
			}
		})
	}
}

// hangUp waits for the relayed target FIN, so the client closes second.
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

func closeRST(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
}

func (r *rig) run(ctx context.Context, k kase) error {
	m := newMessage(k.user, k.pass, r.target, payload()[:k.size])
	segs := m.segments(splits[k.split].cuts(m))
	got, err := r.exchange(ctx, k.user, segs, len(m.early())+len(probe))
	if _, classified := errors.AsType[*failure](err); classified {
		return err
	}
	return verdict(m.early(), got, err)
}

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
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(done)
	wg.Go(func() {
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
	})

	if err := handshakeReplies(c, user); err != nil {
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

// verdict classifies what came back for early, then the probe.
func verdict(early, got []byte, err error) error {
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

// auth {none, u/p} × ATYP {IPv4, domain, IPv6} × early data {0, 64 B,
// 1.5 KiB, 64 KiB} × 7 write splits.
func TestReadiness(t *testing.T) {
	ks := matrix()
	errs := make([]error, len(ks))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, k := range ks {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			r, err := startRig(newServer(k.user, k.pass), k.host, nil)
			if err != nil {
				errs[i] = &failure{"setup", err}
				return
			}
			defer r.close()
			errs[i] = r.run(t.Context(), k)
		})
	}
	wg.Wait()
	failed := make([][]string, len(columns))
	for i, k := range ks {
		if errs[i] != nil {
			failed[k.col] = append(failed[k.col], fmt.Sprintf("%v: %v", k, errs[i]))
		}
	}
	for col, fs := range failed {
		if len(fs) > 0 {
			t.Errorf("cell %s: %d failures:\n%s", columns[col], len(fs), strings.Join(fs, "\n"))
		}
	}
	if !t.Failed() {
		t.Logf("%d cases, every cell of %v passes", len(ks), columns)
	}
}

// A FIN arriving in the handshake read still comes after the early data.
func TestReadinessCloseWrite(t *testing.T) {
	for _, size := range []int{0, 1, 64, 1536, 64 << 10} {
		for _, user := range []string{"", "user"} {
			t.Run(fmt.Sprintf("%s/%d", user, size), func(t *testing.T) {
				s := newServer(user, "pass")
				target := echoTCP(t, "127.0.0.1:0")
				c := dial(t, serve(t, s))
				m := newMessage(user, "pass", target, payload()[:size])
				go func() {
					_, _ = c.Write(m.wire)
					_ = c.CloseWrite()
				}()
				if err := handshakeReplies(c, user); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, m.early()) {
					t.Fatalf("echo: %d bytes, %v; want %d", len(got), err, size)
				}
			})
		}
	}
}

// A u/p client awaiting selection+status before its request gets them: flush before a blocking read.
func TestReadinessFlushBeforeRead(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	c := dial(t, serve(t, newServer("user", "pass")))
	if _, err := c.Write(cat(greeting(wire.MethodUserPass), userPass("user", "pass"))); err != nil {
		t.Fatal(err)
	}
	expect(t, c, []byte{5, 2, 1, 0})
	time.Sleep(segGap)
	if _, err := c.Write(cat(request(wire.CmdConnect, target), []byte("early"))); err != nil {
		t.Fatal(err)
	}
	if rep, _ := readReply(t, c, wire.CmdConnect); rep != 0 {
		t.Fatal(rep)
	}
	expect(t, c, []byte("early"))
}

// No client read during a slow dial, and no deadlock under flow control; the selection goes ahead.
func TestReadinessSlowDial(t *testing.T) {
	for _, size := range []int{64 << 10, 1 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			target := echoTCP(t, "127.0.0.1:0")
			s := open()
			s.Handler = &server.ConnectHandler{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				time.Sleep(200 * time.Millisecond)
				return new(net.Dialer).DialContext(ctx, network, addr)
			}}
			c := dial(t, serve(t, s))
			m := newMessage("", "", target, payload()[:size])
			var wg sync.WaitGroup
			defer wg.Wait()
			start := time.Now()
			wg.Go(func() {
				_, _ = c.Write(m.wire)
				_ = c.CloseWrite()
			})
			expect(t, c, []byte{5, 0})
			if d := time.Since(start); d > 150*time.Millisecond {
				t.Errorf("method selection after %v: not ahead of the slow dial", d)
			}
			if rep, _ := readReply(t, c, wire.CmdConnect); rep != 0 {
				t.Fatal(rep)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, m.early()) {
				t.Fatalf("echo: %d of %d bytes, %v", len(got), size, err)
			}
		})
	}
}

// The target speaks first (SMTP, SSH banners).
func TestReadinessTargetFirst(t *testing.T) {
	ln := listenLoopback(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("220 banner\r\n"))
		_, _ = io.Copy(c, c)
	}()
	c := dial(t, serve(t, open()))
	if _, err := c.Write(newMessage("", "", ln.Addr().String(), nil).wire); err != nil {
		t.Fatal(err)
	}
	if err := handshakeReplies(c, ""); err != nil {
		t.Fatal(err)
	}
	expect(t, c, []byte("220 banner\r\n"))
	_, _ = c.Write([]byte("EHLO\r\n"))
	expect(t, c, []byte("EHLO\r\n"))
}

// A pipelined client gets at most two server writes before the relay.
func TestReadinessSegments(t *testing.T) {
	for _, user := range []string{"", "user"} {
		t.Run("auth="+user, func(t *testing.T) {
			target := echoTCP(t, "127.0.0.1:0")
			ln := spyListener{listenLoopback(t), make(chan *spyConn, 1)}
			s := newServer(user, "pass")
			s.Handler = server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
				return (&server.ConnectHandler{Filter: server.AllowAll}).ServeSOCKS(ctx, r)
			})
			c := dial(t, serveLn(t, s, ln))
			_, _ = c.Write(newMessage(user, "pass", target, nil).wire)
			if err := handshakeReplies(c, user); err != nil {
				t.Fatal(err)
			}
			if n := (<-ln.spies).writes.Load(); n > 2 {
				t.Errorf("%d server writes before the relay, want ≤ 2", n)
			}
		})
	}
}
