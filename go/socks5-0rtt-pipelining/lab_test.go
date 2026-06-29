package zerortt

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/txthinking/socks5"
)

// In-process comparison lab: an echo target, an unmodified txthinking proxy, a
// latency shim, a round-trip counter, and the sequential / pipelined comparison
// dialers — enough to prove 0-RTT delivery and contrast the strategies without
// an external proxy.

// latencyConn delays each Write and Read by Delay, simulating a link with one-way
// latency Delay (RTT 2*Delay); wrapping only the client<->proxy socket isolates
// the RTT that pipelining targets, since loopback is otherwise ~instant.
type latencyConn struct {
	net.Conn
	Delay time.Duration
}

func (l *latencyConn) Write(p []byte) (int, error) {
	time.Sleep(l.Delay)
	return l.Conn.Write(p)
}

func (l *latencyConn) Read(b []byte) (int, error) {
	n, err := l.Conn.Read(b)
	time.Sleep(l.Delay)
	return n, err
}

// countingConn counts Writes and Reads on the proxy socket. The decisive 0-RTT
// signal is zero reads at the moment the first app byte is written.
type countingConn struct {
	net.Conn
	writes atomic.Int64
	reads  atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(p) }
func (c *countingConn) Read(b []byte) (int, error)  { c.reads.Add(1); return c.Conn.Read(b) }

// echoTarget is a TCP server that echoes everything and timestamps each
// connection's first byte.
type echoTarget struct {
	addr     string
	arrivals chan time.Time
}

// startEchoTarget starts an echo server on loopback, closed at test end.
func startEchoTarget(t testing.TB) *echoTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	et := &echoTarget{addr: ln.Addr().String(), arrivals: make(chan time.Time, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go et.serve(c)
		}
	}()
	return et
}

func (et *echoTarget) serve(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 32*1024)
	first := true
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if first {
				first = false
				select {
				case et.arrivals <- time.Now():
				default:
				}
			}
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// firstByteArrival returns when the next connection's first byte arrived.
func (et *echoTarget) firstByteArrival(timeout time.Duration) (time.Time, bool) {
	select {
	case ts := <-et.arrivals:
		return ts, true
	case <-time.After(timeout):
		return time.Time{}, false
	}
}

// startProxy starts a stock txthinking DefaultHandle server on loopback (empty
// user/pass => no-auth) — unmodified, to prove early data needs no server
// change. Shut down at test end.
func startProxy(t testing.TB, user, pass string) string {
	t.Helper()
	// Probe a free port, then hand it to txthinking (which binds TCP+UDP on it).
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())

	host, _, _ := net.SplitHostPort(addr)
	srv, err := socks5.NewClassicServer(addr, host, user, pass, 0, 0)
	require.NoError(t, err)
	go func() { _ = srv.ListenAndServe(nil) }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 2*time.Second, 20*time.Millisecond, "proxy did not come up at %s", addr)
	return addr
}

// dialFunc creates a fresh proxy socket, used to inject latency/counting shims.
type dialFunc func() (net.Conn, error)

// dialSequential is the RFC 1928 baseline: every handshake round trip completes
// before the caller writes a single application byte.
func dialSequential(proxyAddr, user, pass, dst string, dial dialFunc) (net.Conn, error) {
	cl, _ := socks5.NewClient(proxyAddr, user, pass, 0, 0)
	cl.DialTCP = func(network, laddr, raddr string) (net.Conn, error) { return dial() }
	return cl.Dial("tcp", dst)
}

// dialPipelined coalesces the handshake into one write but still waits for the
// replies before the caller may send — the round trip 0-RTT removes.
func dialPipelined(proxyAddr, user, pass, dst string, dial dialFunc) (net.Conn, error) {
	method := socks5.MethodNone
	if user != "" && pass != "" {
		method = socks5.MethodUsernamePassword
	}
	pre, err := buildHandshake(method, user, pass, dst)
	if err != nil {
		return nil, err
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(pre); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write handshake: %w", err)
	}
	if err := readHandshakeReplies(conn, method); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// readHandshakeReplies validates the method/[auth]/CONNECT replies, mirroring
// Conn.readReplies for the comparison path.
func readHandshakeReplies(conn net.Conn, method byte) error {
	nrep, err := socks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read method reply: %w", err)
	}
	if nrep.Method != method {
		return fmt.Errorf("server selected method 0x%02x, expected 0x%02x", nrep.Method, method)
	}
	if method == socks5.MethodUsernamePassword {
		arep, err := socks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			return fmt.Errorf("read auth reply: %w", err)
		}
		if arep.Status != socks5.UserPassStatusSuccess {
			return fmt.Errorf("authenticate: %w", socks5.ErrUserPassAuth)
		}
	}
	rep, err := socks5.NewReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if rep.Rep != socks5.RepSuccess {
		return fmt.Errorf("connect rejected (rep=0x%02x)", rep.Rep)
	}
	return nil
}

// roundTrip writes payload through conn and asserts it comes back echoed.
func roundTrip(t testing.TB, conn net.Conn, payload []byte) {
	t.Helper()
	_, err := conn.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}
