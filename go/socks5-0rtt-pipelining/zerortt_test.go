package zerortt

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// countingDialer wires a Dialer through a countingConn so a test can inspect how
// many writes/reads hit the proxy socket. The accessor returns the countingConn
// captured on the most recent dial.
func countingDialer(proxyAddr, user, pass string) (*Dialer, func() *countingConn) {
	var cc *countingConn
	d := &Dialer{
		ProxyAddress: proxyAddr,
		Username:     user,
		Password:     pass,
		dialProxy: func(_ context.Context, network, address string) (net.Conn, error) {
			raw, err := net.Dial(network, address)
			if err != nil {
				return nil, err
			}
			cc = &countingConn{Conn: raw}
			return cc, nil
		},
	}
	return d, func() *countingConn { return cc }
}

// TestEarlyDataReachesTargetNoAuth is the core claim: against an unmodified
// txthinking server, bytes appended to the handshake (before any reply is read)
// reach the target and echo back, having read nothing from the proxy first.
func TestEarlyDataReachesTargetNoAuth(t *testing.T) {
	target := startEchoTarget(t)
	d, counter := countingDialer(startProxy(t, "", ""), "", "")

	conn, err := d.DialContext(context.Background(), "tcp", target.addr)
	require.NoError(t, err)
	defer conn.Close()
	cc := counter()
	require.Zero(t, cc.writes.Load(), "handshake is deferred until the first Write")

	payload := []byte("hello-0rtt-early-data")
	n, err := conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n, "Write reports app bytes only, not the handshake")
	require.EqualValues(t, 1, cc.writes.Load(), "one write carries handshake+data")
	require.Zero(t, cc.reads.Load(), "0-RTT: app data sent before reading any reply")

	require.Equal(t, payload, readN(t, conn, len(payload)))
	_, ok := target.firstByteArrival(time.Second)
	require.True(t, ok, "target recorded a first-byte arrival")
}

// TestEarlyDataReachesTargetUserPass proves the same through the user/pass auth
// path (greeting + auth + CONNECT + early data in one write).
func TestEarlyDataReachesTargetUserPass(t *testing.T) {
	target := startEchoTarget(t)
	d, counter := countingDialer(startProxy(t, "user", "pass"), "user", "pass")

	conn, err := d.DialContext(context.Background(), "tcp", target.addr)
	require.NoError(t, err)
	defer conn.Close()

	payload := []byte("hello-auth-0rtt")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.Zero(t, counter().reads.Load(), "0-RTT holds on the auth path too")
	require.Equal(t, payload, readN(t, conn, len(payload)))
}

// TestConcurrentReadWriteCoalesces validates ClientDataWait: a Read already
// blocked (as net/http's readLoop is while the writeLoop prepares the request)
// must not flush a bare handshake before the first Write coalesces its payload.
// Coalescing succeeded iff exactly one write reached the proxy.
func TestConcurrentReadWriteCoalesces(t *testing.T) {
	target := startEchoTarget(t)
	d, counter := countingDialer(startProxy(t, "", ""), "", "")

	conn, err := d.DialContext(context.Background(), "tcp", target.addr)
	require.NoError(t, err)
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

	time.Sleep(2 * time.Millisecond) // let the reader enter its ClientDataWait window
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, payload, <-done)
	require.EqualValues(t, 1, counter().writes.Load(), "payload coalesced into the single handshake write")
}

// TestHTTPThroughZeroRTT drives a real net/http request through the dialer,
// proving it is a drop-in http.Transport.DialContext.
func TestHTTPThroughZeroRTT(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.URL.Path)
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	defer backend.Close()

	d := &Dialer{ProxyAddress: startProxy(t, "", "")}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{Protocols: protocols, DisableKeepAlives: true, DialContext: d.DialContext}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(backend.URL + "/zero-rtt")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok:/zero-rtt", string(body))
	require.Equal(t, "/zero-rtt", resp.Header.Get("X-Echo"))
}

// TestHTTPSThroughZeroRTT exercises the headline case: the TLS ClientHello is
// the 0-RTT early data. It runs over the in-process (early-data-safe) txthinking
// proxy on both the no-auth and user/pass paths, which is what a real HTTPS
// fetch through the dialer does.
func TestHTTPSThroughZeroRTT(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	defer backend.Close()

	for _, auth := range []struct{ user, pass string }{{"", ""}, {"user", "pass"}} {
		name := "no-auth"
		if auth.user != "" {
			name = "user-pass"
		}
		t.Run(name, func(t *testing.T) {
			d := &Dialer{ProxyAddress: startProxy(t, auth.user, auth.pass), Username: auth.user, Password: auth.pass}
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			tr := &http.Transport{
				Protocols:         protocols,
				DisableKeepAlives: true,
				DialContext:       d.DialContext,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			}
			defer tr.CloseIdleConnections()

			resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(backend.URL + "/https-0rtt")
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, "ok:/https-0rtt", string(body))
		})
	}
}

// TestFastOpenDeliversData exercises the FastOpen path. The in-process proxy is
// a plain (non-TFO) listener, so tfo-go's Fallback is taken — which must still
// deliver the handshake and early data, and connect only on the first I/O.
func TestFastOpenDeliversData(t *testing.T) {
	target := startEchoTarget(t)
	d := &Dialer{
		ProxyAddress: startProxy(t, "", ""),
		FastOpen:     true,
		NetDialer:    &net.Dialer{Timeout: 3 * time.Second},
	}

	conn, err := d.DialContext(context.Background(), "tcp", target.addr)
	require.NoError(t, err)
	defer conn.Close()
	require.Nil(t, conn.LocalAddr(), "a FastOpen conn is not connected before first I/O")

	payload := []byte("hello-fastopen")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NotNil(t, conn.LocalAddr(), "connected after the first write")
	require.Equal(t, payload, readN(t, conn, len(payload)))
}

// TestServerSpeaksFirstFallback covers a read-first protocol (SMTP/SSH-style
// banner): with no early data to coalesce, the first Read flushes the handshake
// alone (degrading to handshake pipelining) and the banner is delivered.
func TestServerSpeaksFirstFallback(t *testing.T) {
	banner := []byte("220 hello from server\r\n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
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

	d := &Dialer{ProxyAddress: startProxy(t, "", "")}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, banner, readN(t, conn, len(banner)))
	roundTrip(t, conn, []byte("EHLO")) // a normal exchange still works afterwards
}

// TestConnectFailureSurfacedOnRead confirms the optimism semantics: an
// unreachable target accepts the optimistic write but surfaces the failure on
// the first Read, detectably via errors.Is.
func TestConnectFailureSurfacedOnRead(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := dead.Addr().String()
	require.NoError(t, dead.Close())

	d := &Dialer{ProxyAddress: startProxy(t, "", "")}
	conn, err := d.DialContext(context.Background(), "tcp", deadAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("data that will go nowhere"))
	require.NoError(t, err, "the optimistic write succeeds at the socket level")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = conn.Read(make([]byte, 16))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrConnectRejected) || errors.Is(err, io.EOF),
		"failure must be detectable via errors.Is, got %v", err)
}

func TestDialerFromURL(t *testing.T) {
	tests := []struct {
		url, proxy, user, pass string
		wantErr                bool
	}{
		{url: "socks5://127.0.0.1:1080", proxy: "127.0.0.1:1080"},
		{url: "socks5://u:p@proxy.example:9050", proxy: "proxy.example:9050", user: "u", pass: "p"},
		{url: "socks5h://host", proxy: "host:1080"}, // default port
		{url: "http://host:1080", wantErr: true},    // wrong scheme
		{url: "socks5://", wantErr: true},           // no host
	}
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			d, err := DialerFromURL(tc.url)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.proxy, d.ProxyAddress)
			require.Equal(t, tc.user, d.Username)
			require.Equal(t, tc.pass, d.Password)
		})
	}
}

func TestUnsupportedNetwork(t *testing.T) {
	d := &Dialer{ProxyAddress: "127.0.0.1:1080"}
	_, err := d.DialContext(context.Background(), "udp", "example.com:53")
	require.Error(t, err)
}

// TestLatencyOrdering demonstrates the wall-clock payoff over a simulated
// high-latency link: first-byte-at-target falls sequential -> pipelined -> 0-RTT.
// The per-syscall latency shim inflates the gap (it over-counts the multi-read
// CONNECT reply), so assert only the ordering; see the README for the model.
func TestLatencyOrdering(t *testing.T) {
	if testing.Short() {
		t.Skip("latency demo skipped in -short")
	}
	target := startEchoTarget(t)
	proxyAddr := startProxy(t, "", "")

	const delay = 12 * time.Millisecond
	latencyDial := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		return &latencyConn{Conn: raw, Delay: delay}, nil
	}
	payload := []byte("PING")

	measure := func(open func() (net.Conn, error)) time.Duration {
		select { // drain any stale arrival
		case <-target.arrivals:
		default:
		}
		start := time.Now()
		conn, err := open()
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write(payload)
		require.NoError(t, err)
		arr, ok := target.firstByteArrival(3 * time.Second)
		require.True(t, ok)
		return arr.Sub(start)
	}

	zeroDialer := &Dialer{
		ProxyAddress: proxyAddr,
		dialProxy: func(_ context.Context, network, address string) (net.Conn, error) {
			raw, err := net.Dial(network, address)
			if err != nil {
				return nil, err
			}
			return &latencyConn{Conn: raw, Delay: delay}, nil
		},
	}

	seq := measure(func() (net.Conn, error) { return dialSequential(proxyAddr, "", "", target.addr, latencyDial) })
	pipe := measure(func() (net.Conn, error) { return dialPipelined(proxyAddr, "", "", target.addr, latencyDial) })
	zero := measure(func() (net.Conn, error) { return zeroDialer.DialContext(context.Background(), "tcp", target.addr) })

	t.Logf("first byte at target (Rcp/2=%v): sequential=%v pipelined=%v 0-rtt=%v",
		delay, seq.Round(time.Millisecond), pipe.Round(time.Millisecond), zero.Round(time.Millisecond))
	require.Less(t, zero, pipe, "0-rtt should beat pipelined")
	require.Less(t, pipe, seq, "pipelined should beat sequential")
}

// TestRoundTripEconomy asserts the reads-before-first-app-byte ladder that
// defines the technique: sequential and pipelined read replies before the app
// can send, while 0-RTT reads nothing.
func TestRoundTripEconomy(t *testing.T) {
	target := startEchoTarget(t)
	proxyAddr := startProxy(t, "", "")
	payload := []byte("PING")

	for _, tc := range []struct {
		name string
		dial func(dialFunc) (net.Conn, error)
	}{
		{"sequential", func(d dialFunc) (net.Conn, error) { return dialSequential(proxyAddr, "", "", target.addr, d) }},
		{"pipelined", func(d dialFunc) (net.Conn, error) { return dialPipelined(proxyAddr, "", "", target.addr, d) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cc *countingConn
			conn, err := tc.dial(func() (net.Conn, error) {
				raw, err := net.Dial("tcp", proxyAddr)
				if err != nil {
					return nil, err
				}
				cc = &countingConn{Conn: raw}
				return cc, nil
			})
			require.NoError(t, err)
			defer conn.Close()
			require.NotZero(t, cc.reads.Load(), "replies are read before app data")
			roundTrip(t, conn, payload)
		})
	}

	t.Run("0-rtt", func(t *testing.T) {
		d, counter := countingDialer(proxyAddr, "", "")
		conn, err := d.DialContext(context.Background(), "tcp", target.addr)
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write(payload)
		require.NoError(t, err)
		require.Zero(t, counter().reads.Load(), "0-rtt reads nothing before sending")
		require.Equal(t, payload, readN(t, conn, len(payload)))
	})
}

// readN reads exactly n bytes under a short deadline.
func readN(t testing.TB, conn net.Conn, n int) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	b := make([]byte, n)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	return b
}
