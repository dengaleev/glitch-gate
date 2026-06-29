package zerortt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// countingDialer returns a *Dialer wired through a CountingConn so a test can
// inspect how many writes/reads hit the proxy socket, plus an accessor for the
// CountingConn captured on the most recent dial.
func countingDialer(proxyAddr, user, pass string) (*Dialer, func() *CountingConn) {
	var cc *CountingConn
	d := &Dialer{
		ProxyAddress: proxyAddr,
		Username:     user,
		Password:     pass,
		dialProxy: func(_ context.Context, network, address string) (net.Conn, error) {
			raw, err := net.Dial(network, address)
			if err != nil {
				return nil, err
			}
			cc = &CountingConn{Conn: raw}
			return cc, nil
		},
	}
	return d, func() *CountingConn { return cc }
}

// TestEarlyDataReachesTargetNoAuth proves the core claim: against an unmodified
// txthinking/socks5 server, application bytes appended to the handshake (sent
// before any reply is read) are delivered to the target and echoed back.
func TestEarlyDataReachesTargetNoAuth(t *testing.T) {
	target, err := StartEchoTarget()
	if err != nil {
		t.Fatalf("start target: %v", err)
	}
	defer target.Close()
	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close()

	d, counter := countingDialer(proxy.Addr, "", "")
	conn, err := d.DialContext(context.Background(), "tcp", target.Addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	cc := counter()

	// No bytes should have touched the proxy yet: the handshake is deferred.
	if got := cc.Writes(); got != 0 {
		t.Fatalf("expected 0 proxy writes before first Write, got %d", got)
	}

	payload := []byte("hello-0rtt-early-data")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d (must report app bytes only, not handshake)", n, len(payload))
	}

	// The decisive 0-RTT property: the first application payload left the client
	// in a single write, having read *nothing* back from the proxy.
	if w := cc.Writes(); w != 1 {
		t.Fatalf("expected exactly 1 proxy write to carry handshake+data, got %d", w)
	}
	if r := cc.Reads(); r != 0 {
		t.Fatalf("0-RTT violated: read %d batches from proxy before sending app data, want 0", r)
	}

	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	if _, ok := target.FirstByteArrival(time.Second); !ok {
		t.Fatal("target never recorded a first-byte arrival")
	}
}

// TestEarlyDataReachesTargetUserPass proves the same through the user/pass auth
// path (greeting + auth + CONNECT + early data, all in one write).
func TestEarlyDataReachesTargetUserPass(t *testing.T) {
	target, err := StartEchoTarget()
	if err != nil {
		t.Fatalf("start target: %v", err)
	}
	defer target.Close()
	proxy, err := StartProxy("user", "pass")
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close()

	d, counter := countingDialer(proxy.Addr, "user", "pass")
	conn, err := d.DialContext(context.Background(), "tcp", target.Addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-auth-0rtt")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if r := counter().Reads(); r != 0 {
		t.Fatalf("0-RTT violated on auth path: %d reads before app data, want 0", r)
	}

	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

// TestConcurrentReadWriteCoalesces validates the ClientDataWait behavior: when a
// Read is already blocked (as net/http's readLoop is while the writeLoop
// prepares the request), the first Write must still coalesce its payload into
// the single handshake write rather than the Read flushing a bare handshake
// first. Coalescing succeeded iff exactly one write reached the proxy.
func TestConcurrentReadWriteCoalesces(t *testing.T) {
	target, err := StartEchoTarget()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	d, counter := countingDialer(proxy.Addr, "", "")
	conn, err := d.DialContext(context.Background(), "tcp", target.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("concurrent-coalesce")
	done := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(payload))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			done <- nil
			return
		}
		done <- got
	}()

	// Let the reader enter its ClientDataWait window, then write.
	time.Sleep(2 * time.Millisecond)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := <-done
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	if w := counter().Writes(); w != 1 {
		t.Fatalf("coalescing lost under concurrent read/write: %d proxy writes, want 1", w)
	}
}

// TestHTTPThroughZeroRTT drives a real net/http request through the dialer,
// proving it works as a drop-in http.Transport.DialContext and that the HTTP
// request line+headers ride along as early data.
func TestHTTPThroughZeroRTT(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.URL.Path)
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	defer backend.Close()

	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close()

	d := &Dialer{ProxyAddress: proxy.Addr}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{
		Protocols:         protocols,
		DisableKeepAlives: true,
		DialContext:       d.DialContext,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(backend.URL + "/zero-rtt")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s", resp.Status)
	}
	if string(body) != "ok:/zero-rtt" {
		t.Fatalf("body = %q, want %q", body, "ok:/zero-rtt")
	}
	if got := resp.Header.Get("X-Echo"); got != "/zero-rtt" {
		t.Fatalf("X-Echo = %q", got)
	}
}

// TestFastOpenDeliversData exercises the FastOpen code path. The in-process
// txthinking proxy listens with a plain TCP listener (not a TFO listener), so
// tfo-go's Fallback path is taken — which still must deliver the handshake and
// early data correctly. This proves the FastOpen wiring is sound even where
// true SYN-data fast open is unavailable.
func TestFastOpenDeliversData(t *testing.T) {
	target, err := StartEchoTarget()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	d := &Dialer{
		ProxyAddress: proxy.Addr,
		FastOpen:     true,
		NetDialer:    &net.Dialer{Timeout: 3 * time.Second},
	}
	conn, err := d.DialContext(context.Background(), "tcp", target.Addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Before the first I/O a FastOpen Conn is not yet connected.
	if conn.LocalAddr() != nil {
		t.Errorf("expected nil LocalAddr before first I/O, got %v", conn.LocalAddr())
	}

	payload := []byte("hello-fastopen")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if conn.LocalAddr() == nil {
		t.Error("expected non-nil LocalAddr after connect")
	}
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

// TestServerSpeaksFirstFallback covers the read-before-write case (SMTP/SSH-style
// banners): the application reads first, so there is no early data to coalesce.
// The handshake must still flush (degrading to handshake pipelining) so the
// tunnel opens and the target's unsolicited greeting is delivered.
func TestServerSpeaksFirstFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	banner := []byte("220 hello from server\r\n")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write(banner)
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close()

	d := &Dialer{ProxyAddress: proxy.Addr}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(banner))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !bytes.Equal(got, banner) {
		t.Fatalf("banner mismatch: got %q want %q", got, banner)
	}
	if _, err := roundTrip(conn, []byte("EHLO")); err != nil {
		t.Fatalf("post-banner round trip: %v", err)
	}
}

// TestConnectFailureSurfacedOnRead confirms the optimism semantics: when the
// target is unreachable, the early data is sent optimistically but the failure
// is reported to the application on the first Read.
func TestConnectFailureSurfacedOnRead(t *testing.T) {
	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close()

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	d := &Dialer{ProxyAddress: proxy.Addr}
	conn, err := d.DialContext(context.Background(), "tcp", deadAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("data that will go nowhere")); err != nil {
		t.Fatalf("optimistic write should not fail at the socket level: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatal("expected an error on Read after a failed CONNECT, got nil")
	}
	if errors.Is(rerr, io.EOF) {
		t.Logf("Read surfaced failure as EOF (acceptable): %v", rerr)
	}
}

// TestDialerFromURL covers the URL constructor used by CLI callers.
func TestDialerFromURL(t *testing.T) {
	for _, tc := range []struct {
		url       string
		wantProxy string
		wantUser  string
		wantPass  string
		wantErr   bool
	}{
		{"socks5://127.0.0.1:1080", "127.0.0.1:1080", "", "", false},
		{"socks5://u:p@proxy.example:9050", "proxy.example:9050", "u", "p", false},
		{"socks5h://host", "host:1080", "", "", false}, // default port
		{"http://host:1080", "", "", "", true},         // wrong scheme
		{"socks5://", "", "", "", true},                // no host
	} {
		d, err := DialerFromURL(tc.url)
		if tc.wantErr {
			if err == nil {
				t.Errorf("DialerFromURL(%q): expected error, got nil", tc.url)
			}
			continue
		}
		if err != nil {
			t.Errorf("DialerFromURL(%q): %v", tc.url, err)
			continue
		}
		if d.ProxyAddress != tc.wantProxy || d.Username != tc.wantUser || d.Password != tc.wantPass {
			t.Errorf("DialerFromURL(%q) = {%q,%q,%q}, want {%q,%q,%q}",
				tc.url, d.ProxyAddress, d.Username, d.Password, tc.wantProxy, tc.wantUser, tc.wantPass)
		}
	}
}

// TestUnsupportedNetwork rejects non-TCP networks with a clear error.
func TestUnsupportedNetwork(t *testing.T) {
	d := &Dialer{ProxyAddress: "127.0.0.1:1080"}
	if _, err := d.DialContext(context.Background(), "udp", "example.com:53"); err == nil {
		t.Fatal("expected an error for network \"udp\", got nil")
	}
}

// TestLatencyOrdering demonstrates the wall-clock payoff over a simulated
// high-latency client<->proxy link: the time for the first application byte to
// reach the target falls monotonically sequential -> pipelined -> 0-RTT.
//
// The latency shim sleeps per Read/Write syscall, so it over-counts the
// multi-read CONNECT reply and inflates the gap; treat the ordering as the
// signal and see the README for the precise (round-trips x Rcp) model.
func TestLatencyOrdering(t *testing.T) {
	if testing.Short() {
		t.Skip("latency demo skipped in -short")
	}
	target, err := StartEchoTarget()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	const delay = 12 * time.Millisecond
	latencyDial := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", proxy.Addr)
		if err != nil {
			return nil, err
		}
		return &LatencyConn{Conn: raw, Delay: delay}, nil
	}
	payload := []byte("PING")

	measure := func(open func() (net.Conn, error)) time.Duration {
		select {
		case <-target.arrivals:
		default:
		}
		start := time.Now()
		conn, err := open()
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		arr, ok := target.FirstByteArrival(3 * time.Second)
		if !ok {
			t.Fatal("no arrival at target")
		}
		return arr.Sub(start)
	}

	zeroDialer := &Dialer{
		ProxyAddress: proxy.Addr,
		dialProxy: func(_ context.Context, network, address string) (net.Conn, error) {
			raw, err := net.Dial(network, address)
			if err != nil {
				return nil, err
			}
			return &LatencyConn{Conn: raw, Delay: delay}, nil
		},
	}

	seq := measure(func() (net.Conn, error) { return DialSequential(proxy.Addr, "", "", target.Addr, latencyDial) })
	pipe := measure(func() (net.Conn, error) { return DialPipelined(proxy.Addr, "", "", target.Addr, latencyDial) })
	zero := measure(func() (net.Conn, error) { return zeroDialer.DialContext(context.Background(), "tcp", target.Addr) })

	t.Logf("first byte at target (Rcp/2=%v): sequential=%v pipelined=%v 0-rtt=%v", delay, seq.Round(time.Millisecond), pipe.Round(time.Millisecond), zero.Round(time.Millisecond))

	if !(zero < pipe) {
		t.Errorf("expected 0-rtt (%v) faster than pipelined (%v)", zero, pipe)
	}
	if !(pipe < seq) {
		t.Errorf("expected pipelined (%v) faster than sequential (%v)", pipe, seq)
	}
}

// TestRoundTripEconomy contrasts the three strategies on the same in-process
// proxy and asserts the reads-before-first-app-byte ladder that defines the
// technique: sequential and handshake-pipelined both read replies before the
// app can send, while 0-RTT reads nothing.
func TestRoundTripEconomy(t *testing.T) {
	target, err := StartEchoTarget()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	proxy, err := StartProxy("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	payload := []byte("PING")

	for _, tc := range []struct {
		name string
		dial func(DialFunc) (net.Conn, error)
	}{
		{"sequential", func(d DialFunc) (net.Conn, error) { return DialSequential(proxy.Addr, "", "", target.Addr, d) }},
		{"pipelined", func(d DialFunc) (net.Conn, error) { return DialPipelined(proxy.Addr, "", "", target.Addr, d) }},
	} {
		var cc *CountingConn
		d := func() (net.Conn, error) {
			raw, err := net.Dial("tcp", proxy.Addr)
			if err != nil {
				return nil, err
			}
			cc = &CountingConn{Conn: raw}
			return cc, nil
		}
		conn, err := tc.dial(d)
		if err != nil {
			t.Fatalf("%s dial: %v", tc.name, err)
		}
		readsBeforeData := cc.Reads()
		if _, err := roundTrip(conn, payload); err != nil {
			t.Fatalf("%s round trip: %v", tc.name, err)
		}
		_ = conn.Close()
		if readsBeforeData == 0 {
			t.Fatalf("%s: expected reply reads before app data, got 0", tc.name)
		}
		t.Logf("%-10s reads before first app byte: %d", tc.name, readsBeforeData)
	}

	// 0-RTT: zero reads before the app byte is on the wire.
	d, counter := countingDialer(proxy.Addr, "", "")
	conn, err := d.DialContext(context.Background(), "tcp", target.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if r := counter().Reads(); r != 0 {
		t.Fatalf("0-rtt: expected 0 reads before app data, got %d", r)
	}
	t.Logf("%-10s reads before first app byte: %d", "0-rtt", counter().Reads())

	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("0-rtt read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("0-rtt echo mismatch: got %q want %q", got, payload)
	}
}
