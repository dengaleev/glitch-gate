package server_test

// The L1/L2 readiness matrix of ../socks5-zero-rtt-bench, ported stdlib-only, plus extra cells.

import (
	"bytes"
	"context"
	"encoding/binary"
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

// Non-repeating, so loss or reorder shows.
var payload = sync.OnceValue(func() []byte {
	b := make([]byte, 1<<20)
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

func s5Greeting(user string) []byte {
	if user != "" {
		return []byte{5, 1, 2}
	}
	return []byte{5, 1, 0}
}

func s5Auth(user, pass string) []byte {
	b := append([]byte{1, byte(len(user))}, user...)
	return append(append(b, byte(len(pass))), pass...)
}

func s5Connect(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	b := []byte{5, 1, 0}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		b = append(append(b, 3, byte(len(host))), host...)
	case ip.To4() != nil:
		b = append(append(b, 1), ip.To4()...)
	default:
		b = append(append(b, 4), ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// s5ReadReplies reads nothing past the CONNECT reply.
func s5ReadReplies(r io.Reader, user string) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if want := s5Greeting(user)[2]; b != [2]byte{5, want} {
		return fmt.Errorf("method selection %x, want 05%02x", b, want)
	}
	if user != "" {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return fmt.Errorf("read auth status: %w", err)
		}
		if b[1] != 0 {
			return fmt.Errorf("auth rejected (status 0x%02x)", b[1])
		}
	}
	rep, _, err := wire.ReadReply(r, wire.CmdConnect)
	if err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if rep != wire.ReplySucceeded {
		return fmt.Errorf("connect rejected (rep 0x%02x)", uint8(rep))
	}
	return nil
}

// message is greeting, [auth], CONNECT, early data, as one zero-RTT write.
type message struct {
	wire      []byte
	hsLen     int // handshake bytes; the rest of wire is early data
	partEnds  []int
	fieldLens []int // every protocol field, in order
}

func newMessage(user, pass, target string, early []byte) (message, error) {
	req, err := s5Connect(target)
	if err != nil {
		return message{}, err
	}
	parts := [][]byte{s5Greeting(user)}
	fields := []int{1, 1, 1}
	if user != "" {
		parts = append(parts, s5Auth(user, pass))
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
	return m, nil
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

func newServer(user, pass string) *server.Server {
	s := open()
	if user != "" {
		s.Auth = []server.Authenticator{server.UserPass{Users: map[string]string{user: pass}}}
	}
	return s
}

func startRig(s *server.Server, host string) (*rig, error) {
	r := &rig{srv: s}
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
	r.wg.Go(func() { _ = s.Serve(proxyLn) })
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

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		ln.Close()
	}
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

// For localhost: 127.0.0.1 and ::1 at one port, whichever the server resolves.
func echoListeners(host string) ([]net.Listener, string, error) {
	ips := []string{host}
	if host == "localhost" {
		ips = []string{"127.0.0.1"}
		if hasIPv6() {
			ips = append(ips, "::1")
		}
	}
	for range 100 {
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

	if err := s5ReadReplies(c, user); err != nil {
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
			r, err := startRig(newServer(k.user, k.pass), k.host)
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

// I6: a FIN arriving in the handshake read still comes after the early data.
func TestReadinessCloseWrite(t *testing.T) {
	for _, size := range []int{0, 1, 64, 1536, 64 << 10} {
		for _, user := range []string{"", "user"} {
			t.Run(fmt.Sprintf("%s/%d", user, size), func(t *testing.T) {
				s := newServer(user, "pass")
				target := echoTCP(t, "127.0.0.1:0")
				c := dial(t, serve(t, s))
				m, _ := newMessage(user, "pass", target, payload()[:size])
				go func() {
					_, _ = c.Write(m.wire)
					_ = c.CloseWrite()
				}()
				if err := s5ReadReplies(c, user); err != nil {
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
	if _, err := c.Write(cat(s5Greeting("user"), s5Auth("user", "pass"))); err != nil {
		t.Fatal(err)
	}
	expect(t, c, []byte{5, 2, 1, 0})
	req, _ := s5Connect(target)
	time.Sleep(segGap)
	if _, err := c.Write(cat(req, []byte("early"))); err != nil {
		t.Fatal(err)
	}
	if rep, _ := readReply(t, c, wire.CmdConnect); rep != 0 {
		t.Fatal(rep)
	}
	expect(t, c, []byte("early"))
}

// slowDial: no client read during the dial, and no deadlock under flow control.
func slowDial(d time.Duration) *server.ConnectHandler {
	return &server.ConnectHandler{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		time.Sleep(d)
		return new(net.Dialer).DialContext(ctx, network, addr)
	}}
}

func TestReadinessSlowDial(t *testing.T) {
	for _, size := range []int{64 << 10, 1 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			target := echoTCP(t, "127.0.0.1:0")
			s := open()
			s.Handler = slowDial(200 * time.Millisecond)
			c := dial(t, serve(t, s))
			m, _ := newMessage("", "", target, payload()[:size])
			var wg sync.WaitGroup
			defer wg.Wait()
			start := time.Now()
			wg.Go(func() {
				_, _ = c.Write(m.wire)
				_ = c.CloseWrite()
			})
			expect(t, c, []byte{5, 0})
			if d := time.Since(start); d > 150*time.Millisecond {
				t.Errorf("method selection after %v: not ahead of the slow dial (I7)", d)
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
	m, _ := newMessage("", "", ln.Addr().String(), nil)
	if _, err := c.Write(m.wire); err != nil {
		t.Fatal(err)
	}
	if err := s5ReadReplies(c, ""); err != nil {
		t.Fatal(err)
	}
	expect(t, c, []byte("220 banner\r\n"))
	_, _ = c.Write([]byte("EHLO\r\n"))
	expect(t, c, []byte("EHLO\r\n"))
}

type writeCounter struct {
	net.Listener
	writes chan *countConn
}

type countConn struct {
	net.Conn
	n atomic.Int32
}

func (c *countConn) Write(b []byte) (int, error) {
	c.n.Add(1)
	return c.Conn.Write(b)
}

func (l *writeCounter) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc := &countConn{Conn: c}
	l.writes <- cc
	return cc, nil
}

// I7: a pipelined client gets at most two server writes before the relay.
func TestReadinessSegments(t *testing.T) {
	for _, user := range []string{"", "user"} {
		t.Run("auth="+user, func(t *testing.T) {
			target := echoTCP(t, "127.0.0.1:0")
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			wc := &writeCounter{Listener: ln, writes: make(chan *countConn, 1)}
			s := newServer(user, "pass")
			s.Handler = server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
				return (&server.ConnectHandler{Filter: server.AllowAll}).ServeSOCKS(ctx, r)
			})
			go func() { _ = s.Serve(wc) }()
			defer s.Close()
			c := dial(t, ln.Addr().String())
			m, _ := newMessage(user, "pass", target, nil)
			_, _ = c.Write(m.wire)
			if err := s5ReadReplies(c, user); err != nil {
				t.Fatal(err)
			}
			if n := (<-wc.writes).n.Load(); n > 2 {
				t.Errorf("%d server writes before the relay, want ≤ 2", n)
			}
		})
	}
}
