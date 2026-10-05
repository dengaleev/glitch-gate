package server_test

// The shared harness: servers, scripted raw SOCKS clients built on wire, echo targets, spies, loggers.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestMain(m *testing.M) {
	base := runtime.NumGoroutine()
	code := m.Run()
	if code == 0 {
		if err := settle(base, 10*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

// settle ignores the fuzz engine's os/signal goroutine.
func settle(base int, wait time.Duration) error {
	count := func() (int, string) {
		buf := make([]byte, 1<<20)
		all := string(buf[:runtime.Stack(buf, true)])
		n := 0
		for g := range strings.SplitSeq(all, "\n\n") {
			if !strings.Contains(g, "os/signal.") {
				n++
			}
		}
		return n, all
	}
	for end := time.Now().Add(wait); ; time.Sleep(5 * time.Millisecond) {
		n, all := count()
		if n <= base {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("goroutines: %d > baseline %d\n%s", n, base, all)
		}
	}
}

// noLeaks must be registered first: cleanups run LIFO.
func noLeaks(t *testing.T) {
	base := runtime.NumGoroutine()
	t.Cleanup(func() {
		if err := settle(base, 5*time.Second); err != nil {
			t.Error(err)
		}
	})
}

// Servers.

// open serves CONNECT to any target without auth.
func open() *server.Server {
	return &server.Server{
		Handler:  &server.ConnectHandler{Filter: server.AllowAll},
		ErrorLog: quietLog,
	}
}

// newServer is open with a single user, or none for "".
func newServer(user, pass string) *server.Server {
	s := open()
	if user != "" {
		s.Auth = []server.Authenticator{server.UserPass{Users: map[string]string{user: pass}}}
	}
	return s
}

// withHandler is open serving h.
func withHandler(h server.Handler) *server.Server {
	s := open()
	s.Handler = h
	return s
}

func listen(t testing.TB, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func listenLoopback(t testing.TB) net.Listener { return listen(t, "127.0.0.1:0") }

// serveLn serves ln until the test ends, then requires a clean Shutdown and ErrServerClosed.
func serveLn(t testing.TB, s *server.Server, ln net.Listener) string {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; !errors.Is(err, server.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

func serve(t testing.TB, s *server.Server) string { return serveLn(t, s, listenLoopback(t)) }

// serveOne runs ServeConn for one TCP conn and returns the client side and ServeConn's result.
func serveOne(t testing.TB, s *server.Server) (*net.TCPConn, <-chan error) {
	t.Helper()
	ln := listenLoopback(t)
	errc, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		errc <- s.ServeConn(context.Background(), c)
	}()
	c := dial(t, ln.Addr().String())
	t.Cleanup(func() { c.Close(); <-done })
	return c, errc
}

func result(t testing.TB, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("ServeConn did not return")
		return nil
	}
}

// servePipe runs ServeConn on a net.Pipe: it writes script in pieces cut at the running sums of
// cuts, discards the replies and, with hangUp, closes the client side after the script.
func servePipe(t testing.TB, s *server.Server, script, cuts []byte, hangUp bool) error {
	t.Helper()
	cli, srv := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- s.ServeConn(context.Background(), srv) }()
	var wg sync.WaitGroup
	defer func() { cli.Close(); wg.Wait() }()
	wg.Go(func() { _, _ = io.Copy(io.Discard, cli) })
	wg.Go(func() {
		last := 0
		for _, c := range cuts {
			if i := last + int(c); i < len(script) {
				if _, err := cli.Write(script[last:i]); err != nil {
					return
				}
				last = i
			}
		}
		_, _ = cli.Write(script[last:])
		if hangUp {
			cli.Close()
		}
	})
	select {
	case err := <-errc:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("ServeConn hangs on %x", script)
		return nil
	}
}

// handshakeErr requires a "socks serve" *net.OpError carrying a *socks0.HandshakeError.
func handshakeErr(t testing.TB, err error) *socks0.HandshakeError {
	t.Helper()
	oe, ok := errors.AsType[*net.OpError](err)
	if !ok || oe.Op != "socks serve" || oe.Source == nil || oe.Addr == nil {
		t.Fatalf("not a socks serve OpError: %#v", err)
	}
	if oe.Source.String() == oe.Addr.String() || !strings.HasPrefix(oe.Addr.String(), "127.0.0.1:") {
		t.Errorf("Source %v Addr %v", oe.Source, oe.Addr)
	}
	he, ok := errors.AsType[*socks0.HandshakeError](err)
	if !ok {
		t.Fatalf("no HandshakeError in %v", err)
	}
	return he
}

// Clients.

func dial(t testing.TB, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c.(*net.TCPConn)
}

// ask sends a no-auth greeting and req to proxy and reads the selection and the first reply.
func ask(t testing.TB, proxy string, req []byte) (*net.TCPConn, wire.Reply, wire.Addr) {
	t.Helper()
	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), req))
	expect(t, c, []byte{5, 0})
	rep, bound := readReply(t, c, wire.Command(req[1]))
	return c, rep, bound
}

// askOne is ask over serveOne; req may carry early data.
func askOne(t testing.TB, s *server.Server, req []byte) (*net.TCPConn, wire.Reply, wire.Addr, <-chan error) {
	t.Helper()
	c, errc := serveOne(t, s)
	_, _ = c.Write(cat(greeting(0), req))
	expect(t, c, []byte{5, 0})
	rep, bound := readReply(t, c, wire.Command(req[1]))
	return c, rep, bound, errc
}

func tunnel(t testing.TB, proxy, target string) *net.TCPConn {
	t.Helper()
	c, _, _ := ask(t, proxy, request(wire.CmdConnect, target))
	return c
}

// assoc returns the control conn and the relay address.
func assoc(t testing.TB, proxy, dst string) (*net.TCPConn, *net.UDPAddr) {
	t.Helper()
	c, rep, relay := ask(t, proxy, request(wire.CmdUDPAssociate, dst))
	if rep != 0 {
		t.Fatalf("ASSOCIATE: %v", rep)
	}
	return c, net.UDPAddrFromAddrPort(netip.AddrPortFrom(relay.IP(), relay.Port()))
}

// rawReply sends a no-auth greeting and req and returns everything until EOF, reply or not.
func rawReply(t testing.TB, proxy string, req []byte) []byte {
	t.Helper()
	c := dial(t, proxy)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write(cat(greeting(0), req))
	got, _ := io.ReadAll(c)
	return got
}

// Messages.

func greeting(methods ...wire.Method) []byte {
	b, err := wire.AppendGreeting(nil, methods...)
	if err != nil {
		panic(err)
	}
	return b
}

func request(cmd wire.Command, addr string) []byte {
	b, err := wire.AppendRequest(nil, cmd, mustAddr(addr))
	if err != nil {
		panic(err)
	}
	return b
}

func request4(cmd wire.Command, addr, uid string) []byte {
	b, err := wire.AppendRequest4(nil, cmd, mustAddr(addr), uid)
	if err != nil {
		panic(err)
	}
	return b
}

// rawRequest takes any DOMAINNAME bytes, unvalidated.
func rawRequest(cmd wire.Command, name string, port uint16) []byte {
	b := []byte{5, byte(cmd), 0, 3, byte(len(name))}
	b = append(b, name...)
	return binary.BigEndian.AppendUint16(b, port)
}

func userPass(user, pass string) []byte {
	b, err := wire.AppendUserPass(nil, user, pass)
	if err != nil {
		panic(err)
	}
	return b
}

func mustAddr(s string) wire.Addr {
	a, err := wire.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func cat(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

// Non-repeating, so loss or reorder shows.
var payload = sync.OnceValue(func() []byte {
	b := make([]byte, 1<<20)
	_, _ = rand.NewChaCha8([32]byte{'s', 'o', 'c', 'k', 's', '5'}).Read(b)
	return b
})

// Reading.

func readN(t testing.TB, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read %d bytes: %v (got %x)", n, err, b)
	}
	return b
}

func expect(t testing.TB, r io.Reader, want []byte) {
	t.Helper()
	if got := readN(t, r, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func readReply(t testing.TB, r io.Reader, cmd wire.Command) (wire.Reply, wire.Addr) {
	t.Helper()
	rep, bound, err := wire.ReadReply(r, cmd)
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	return rep, bound
}

// handshakeReplies reads the selection, the u/p status for a user, and a success reply: nothing more.
func handshakeReplies(r io.Reader, user string) error {
	var b [2]byte
	want := [2]byte{5, byte(wire.MethodNoAuth)}
	if user != "" {
		want[1] = byte(wire.MethodUserPass)
	}
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if b != want {
		return fmt.Errorf("method selection %x, want %x", b, want)
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

func expectEOF(t testing.TB, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if len(b) != 0 || err != nil && !isReset(err) {
		t.Fatalf("want EOF, got %x, %v", b, err)
	}
	c.Close()
}

func isReset(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "reset") || errors.Is(err, io.EOF))
}

func timedOut(err error) bool {
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}

func waitFor(t testing.TB, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("timed out waiting")
		}
	}
}

// roundTrip echoes msg; with CloseWrite, up to the relayed FIN.
func roundTrip(t testing.TB, c net.Conn, msg []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		got, err := io.ReadAll(c)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo %q, %v; want %q", got, err, msg)
		}
		return
	}
	expect(t, c, msg)
}

// Targets.

var hasIPv6 = sync.OnceValue(func() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err == nil {
		ln.Close()
	}
	return err == nil
})

// echoOn echoes every conn ln accepts and relays the FIN.
func echoOn(t testing.TB, ln net.Listener) string {
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
				_, _ = io.Copy(io.Discard, c)
			})
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

func echoTCP(t testing.TB, addr string) string { return echoOn(t, listen(t, addr)) }

// echoLocalhost listens on both 127.0.0.1 and ::1 at one port.
func echoLocalhost(t testing.TB) string {
	t.Helper()
	lns, port, err := echoListeners("localhost")
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range lns {
		echoOn(t, ln)
	}
	return net.JoinHostPort("localhost", port)
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

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		ln.Close()
	}
}

// countAccepts closes every conn ln accepts and counts them: a target that must never be reached.
func countAccepts(t testing.TB, ln net.Listener) *atomic.Int32 {
	var n atomic.Int32
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return &n
}

func tcpPair(t testing.TB) (near, far *net.TCPConn) {
	t.Helper()
	ln := listenLoopback(t)
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acc <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := (<-acc).(*net.TCPConn)
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*net.TCPConn), s
}

// UDP.

func echoUDP(t testing.TB, addr string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	})
	t.Cleanup(func() { pc.Close(); wg.Wait() })
	return pc.(*net.UDPConn)
}

func udpSock(t testing.TB) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

// spyUDP reports the source of the first datagram it gets.
func spyUDP(t testing.TB) (*net.UDPConn, <-chan netip.AddrPort) {
	pc := udpSock(t)
	from := make(chan netip.AddrPort, 1)
	go func() {
		b := make([]byte, 100)
		_, ap, err := pc.ReadFromUDPAddrPort(b)
		if err == nil {
			from <- ap
		}
	}()
	return pc, from
}

func dgram(to netip.AddrPort, payload string) []byte {
	h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(to))
	return append(h, payload...)
}

func apOf(a net.Addr) netip.AddrPort { return a.(*net.UDPAddr).AddrPort() }

// recv returns nil on timeout.
func recv(c *net.UDPConn, d time.Duration) []byte {
	_ = c.SetReadDeadline(time.Now().Add(d))
	b := make([]byte, 65536)
	n, err := c.Read(b)
	if err != nil {
		return nil
	}
	return b[:n]
}

// drops records the Dropped trace.
type drops struct {
	mu  sync.Mutex
	got []string
	err []error
}

func (d *drops) trace() *server.ServerTrace {
	return &server.ServerTrace{Dropped: func(_ context.Context, from netip.AddrPort, err error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.got = append(d.got, fmt.Sprint(from, " ", err))
		d.err = append(d.err, err)
	}}
}

func (d *drops) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.got)
}

// wait awaits a drop matching target, or any *wire.ProtocolError for one.
func (d *drops) wait(t testing.TB, target error) {
	t.Helper()
	waitFor(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, err := range d.err {
			if errors.Is(err, target) {
				return true
			}
			if _, ok := target.(*wire.ProtocolError); ok {
				if _, ok := errors.AsType[*wire.ProtocolError](err); ok {
					return true
				}
			}
		}
		return false
	})
}

// assocServer serves h alone, tracing drops into d if set.
func assocServer(h *server.AssociateHandler, d *drops) *server.Server {
	s := withHandler(h)
	if d != nil {
		s.Trace = d.trace()
	}
	return s
}

// Resolvers.

// fakeDNS maps a name to comma-separated IPs; it has no LookupAddr.
type fakeDNS map[string]string

func (f fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var ips []netip.Addr
	for s := range strings.SplitSeq(f[host], ",") {
		if ip, err := netip.ParseAddr(s); err == nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

// dnsServer serves A, AAAA and NXDOMAIN over UDP for a PreferGo net.Resolver.
func dnsServer(t testing.TB, zone map[string][]string) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := dnsAnswer(buf[:n], zone); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	})
	t.Cleanup(func() { pc.Close(); wg.Wait() })
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
}

func dnsAnswer(q []byte, zone map[string][]string) []byte {
	if len(q) < 12 {
		return nil
	}
	var labels []string
	i := 12
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if i+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+5 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i+1:])
	question := q[12 : i+5]
	var answers [][]byte
	ips, found := zone[strings.ToLower(strings.Join(labels, "."))]
	for _, s := range ips {
		ip := netip.MustParseAddr(s)
		if ip.Is4() && qtype == 1 || ip.Is6() && qtype == 28 {
			answers = append(answers, ip.AsSlice())
		}
	}
	rcode := uint16(0)
	if !found {
		rcode = 3
	}
	r := binary.BigEndian.AppendUint16(nil, binary.BigEndian.Uint16(q))
	r = binary.BigEndian.AppendUint16(r, 0x8180|rcode)
	r = binary.BigEndian.AppendUint16(r, 1)
	r = binary.BigEndian.AppendUint16(r, uint16(len(answers)))
	r = append(r, 0, 0, 0, 0)
	r = append(r, question...)
	for _, a := range answers {
		r = append(r, 0xC0, 12)
		r = binary.BigEndian.AppendUint16(r, qtype)
		r = append(r, 0, 1, 0, 0, 0, 60)
		r = binary.BigEndian.AppendUint16(r, uint16(len(a)))
		r = append(r, a...)
	}
	return r
}

// Spies and fakes.

// spyConn logs the copy-path calls a *net.TCPConn gets and counts its Writes.
type spyConn struct {
	*net.TCPConn
	writes atomic.Int32
	mu     sync.Mutex
	calls  []string
}

func (s *spyConn) log(f string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fmt.Sprintf(f, args...))
}

func (s *spyConn) Write(b []byte) (int, error) {
	s.writes.Add(1)
	s.log("Write %q", b)
	return s.TCPConn.Write(b)
}

func (s *spyConn) WriteTo(w io.Writer) (int64, error) {
	s.log("WriteTo %T", w)
	return s.TCPConn.WriteTo(w)
}

func (s *spyConn) ReadFrom(r io.Reader) (int64, error) {
	s.log("ReadFrom %T", r)
	return s.TCPConn.ReadFrom(r)
}

func (s *spyConn) got() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.calls, "; ")
}

// spyListener wraps every accepted conn in a spyConn.
type spyListener struct {
	net.Listener
	spies chan *spyConn
}

func (l spyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	s := &spyConn{TCPConn: c.(*net.TCPConn)}
	l.spies <- s
	return s, nil
}

// errListener returns its errors from Accept in turn, then the inner listener's.
type errListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
}

func (l *errListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

// tempErr is a temporary net.Error with the given text.
type tempErr string

func (e tempErr) Error() string { return string(e) }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

// authFunc is a custom method 0x80.
type authFunc func(context.Context, *server.AuthConn) (any, error)

func (authFunc) Method() wire.Method { return 0x80 }
func (f authFunc) Authenticate(ctx context.Context, c *server.AuthConn) (any, error) {
	return f(ctx, c)
}

// limitWriter takes n bytes, then fails with errFull.
type limitWriter struct {
	w *bytes.Buffer
	n int
}

var errFull = errors.New("full")

func (l *limitWriter) Write(p []byte) (int, error) {
	m := min(len(p), l.n-l.w.Len())
	l.w.Write(p[:m])
	if l.w.Len() >= l.n {
		return m, errFull
	}
	return m, nil
}

// Logs.

var quietLog = log.New(io.Discard, "", 0)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newLogger(w io.Writer) *log.Logger { return log.New(w, "", 0) }

// forged is attacker-influenced text that would forge a log line unless quoted.
const forged = "x\n2026/10/04 00:00:00 FORGED admin login ok\r\x1b[2J"

func logQuoted(out string) bool {
	return !strings.Contains(out, "\nFORGED") && !strings.Contains(out, "\x1b") && strings.Contains(out, `\n2026/10/04`)
}

func traceAll(seen *[]string) *server.ServerTrace {
	var mu sync.Mutex
	add := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		*seen = append(*seen, fmt.Sprintf(format, args...))
	}
	return &server.ServerTrace{
		GotGreeting: func(_ context.Context, m []wire.Method) { add("greeting %v", m) },
		AuthDone:    func(_ context.Context, m wire.Method, id any, err error) { add("auth %v %v %v", m, id, err) },
		GotRequest:  func(_ context.Context, r *server.Request) { add("request %v %v", r.Command, r.Addr) },
		Replied:     func(_ context.Context, rep wire.Reply, b wire.Addr, err error) { add("replied %v %v %v", rep, b, err) },
		Dropped:     func(_ context.Context, from netip.AddrPort, err error) { add("dropped %v %v", from, err) },
		Done: func(_ context.Context, r *server.Request, st server.ConnStats, err error) {
			add("done %v %+v %v", r != nil, st, err)
		},
	}
}
