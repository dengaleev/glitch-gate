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

	var cc *CountingConn
	dial := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", proxy.Addr)
		if err != nil {
			return nil, err
		}
		cc = &CountingConn{Conn: raw}
		return cc, nil
	}

	conn, err := Dial(proxy.Addr, "", "", target.Addr, dial)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

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
		t.Fatalf("0-RTT violated: read %d bytes-batches from proxy before sending app data, want 0", r)
	}

	// And it must actually arrive at the target and echo back intact.
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

	var cc *CountingConn
	dial := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", proxy.Addr)
		if err != nil {
			return nil, err
		}
		cc = &CountingConn{Conn: raw}
		return cc, nil
	}

	conn, err := Dial(proxy.Addr, "user", "pass", target.Addr, dial)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-auth-0rtt")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if r := cc.Reads(); r != 0 {
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

// TestServerSpeaksFirstFallback covers the read-before-write case (SMTP/SSH-style
// banners): the application reads first, so there is no early data to coalesce.
// The handshake must still flush (degrading to handshake pipelining) so the
// tunnel opens and the target's unsolicited greeting is delivered.
func TestServerSpeaksFirstFallback(t *testing.T) {
	// A "banner" target that speaks first, then echoes.
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

	conn, err := Dial(proxy.Addr, "", "", ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read first — this must flush the handshake (no early data) and validate
	// the replies, then surface the banner.
	got := make([]byte, len(banner))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !bytes.Equal(got, banner) {
		t.Fatalf("banner mismatch: got %q want %q", got, banner)
	}

	// And a subsequent write still works (normal, post-handshake).
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

	// Reserve a port and close it so the CONNECT is refused.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	conn, err := Dial(proxy.Addr, "", "", deadAddr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The optimistic write succeeds at the proxy-socket level...
	if _, err := conn.Write([]byte("data that will go nowhere")); err != nil {
		t.Fatalf("optimistic write should not fail at the socket level: %v", err)
	}
	// ...but the CONNECT failure surfaces on the first Read.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatal("expected an error on Read after a failed CONNECT, got nil")
	}
	if errors.Is(rerr, io.EOF) {
		// txthinking replies RepHostUnreachable then closes; depending on
		// timing the client may see the rejecting reply or an EOF. Either is a
		// failure surfaced on Read, which is what matters.
		t.Logf("Read surfaced failure as EOF (acceptable): %v", rerr)
	}
}

// TestHTTPThroughZeroRTT drives a real net/http request through the 0-RTT conn,
// proving it works as a drop-in http.Transport.DialContext and that the HTTP
// request line+headers ride along as early data (http/1.1 writes the request
// before reading the response, so the first Write is the request).
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

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{
		Protocols:         protocols,
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			return Dial(proxy.Addr, "", "", addr, nil)
		},
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

	measure := func(open func() (net.Conn, error), writeFirst bool) time.Duration {
		// Drain any stale arrival.
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
		_ = writeFirst
		return arr.Sub(start)
	}

	seq := measure(func() (net.Conn, error) { return DialSequential(proxy.Addr, "", "", target.Addr, latencyDial) }, false)
	pipe := measure(func() (net.Conn, error) { return DialPipelined(proxy.Addr, "", "", target.Addr, latencyDial) }, false)
	zero := measure(func() (net.Conn, error) { return Dial(proxy.Addr, "", "", target.Addr, latencyDial) }, true)

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

	// Sequential and pipelined complete their handshake (incl. reply reads)
	// before returning, so by the time we write, reads > 0.
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
	var cc *CountingConn
	d := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", proxy.Addr)
		if err != nil {
			return nil, err
		}
		cc = &CountingConn{Conn: raw}
		return cc, nil
	}
	conn, err := Dial(proxy.Addr, "", "", target.Addr, d)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if r := cc.Reads(); r != 0 {
		t.Fatalf("0-rtt: expected 0 reads before app data, got %d", r)
	}
	t.Logf("%-10s reads before first app byte: %d", "0-rtt", cc.Reads())

	// The payload was already written; read the echo back to confirm delivery.
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("0-rtt read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("0-rtt echo mismatch: got %q want %q", got, payload)
	}
}
