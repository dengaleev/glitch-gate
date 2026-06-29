package zerortt

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/txthinking/socks5"
)

// This file is a self-contained, in-process comparison lab: an echo target, an
// unmodified txthinking/socks5 proxy, a per-write/per-read latency shim, a
// round-trip counter, and the three client handshake strategies
// (sequential / handshake-pipelined / 0-RTT data pipelined). It needs no
// external proxy, which is what lets the test prove — against a real txthinking
// server — that 0-RTT early data is delivered to the target.

// LatencyConn adds a fixed one-way delay to every Write (before the bytes hit
// the wire) and every Read (before the bytes are handed to the caller),
// simulating a link whose one-way latency is Delay and whose RTT is 2*Delay.
// Loopback is otherwise ~instant, so wrapping only the client<->proxy socket
// isolates the client<->proxy RTT (Rcp) that pipelining targets.
type LatencyConn struct {
	net.Conn
	Delay time.Duration
}

func (l *LatencyConn) Write(p []byte) (int, error) {
	if l.Delay > 0 {
		time.Sleep(l.Delay)
	}
	return l.Conn.Write(p)
}

func (l *LatencyConn) Read(b []byte) (int, error) {
	n, err := l.Conn.Read(b)
	if l.Delay > 0 {
		time.Sleep(l.Delay)
	}
	return n, err
}

// CountingConn records how many Writes and Reads have been issued on the proxy
// socket. The decisive 0-RTT metric is Reads at the moment the first
// application byte is written: a true 0-RTT client sends application data
// having read nothing back from the proxy.
type CountingConn struct {
	net.Conn
	writes atomic.Int64
	reads  atomic.Int64
}

func (c *CountingConn) Write(p []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(p) }
func (c *CountingConn) Read(b []byte) (int, error)  { c.reads.Add(1); return c.Conn.Read(b) }
func (c *CountingConn) Writes() int                 { return int(c.writes.Load()) }
func (c *CountingConn) Reads() int                  { return int(c.reads.Load()) }

// EchoTarget is a TCP server that echoes everything it receives and timestamps
// the first byte of each connection.
type EchoTarget struct {
	Addr     string
	arrivals chan time.Time
	ln       net.Listener
}

// StartEchoTarget starts an echo server on loopback.
func StartEchoTarget() (*EchoTarget, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t := &EchoTarget{Addr: ln.Addr().String(), arrivals: make(chan time.Time, 16), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go t.serve(c)
		}
	}()
	return t, nil
}

func (t *EchoTarget) serve(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 32*1024)
	first := true
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if first {
				first = false
				select {
				case t.arrivals <- time.Now():
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

// FirstByteArrival blocks until the next connection's first byte arrives (or
// the timeout elapses) and returns its timestamp.
func (t *EchoTarget) FirstByteArrival(timeout time.Duration) (time.Time, bool) {
	select {
	case ts := <-t.arrivals:
		return ts, true
	case <-time.After(timeout):
		return time.Time{}, false
	}
}

func (t *EchoTarget) Close() error { return t.ln.Close() }

// Proxy is an in-process, unmodified txthinking/socks5 server (DefaultHandle).
type Proxy struct {
	Addr   string
	server *socks5.Server
}

// StartProxy starts a txthinking SOCKS5 server on loopback. Empty user/pass =>
// no-auth; both set => user/pass auth. It is the stock DefaultHandle relay — no
// changes for early data.
func StartProxy(user, pass string) (*Proxy, error) {
	// Probe a free port, then hand it to txthinking (which binds TCP+UDP on it).
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	host, _, _ := net.SplitHostPort(addr)
	srv, err := socks5.NewClassicServer(addr, host, user, pass, 0, 0)
	if err != nil {
		return nil, err
	}
	go func() { _ = srv.ListenAndServe(nil) }()

	// Wait until the listener is accepting before returning.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("proxy did not come up at %s: %w", addr, err)
		}
	}
	return &Proxy{Addr: addr, server: srv}, nil
}

func (p *Proxy) Close() error { return p.server.Shutdown() }

// DialFunc creates a fresh proxy socket. Used to inject latency/counting.
type DialFunc func() (net.Conn, error)

// DialSequential performs the classic RFC 1928 sequential handshake (greeting
// -> reply, [auth -> reply], CONNECT -> reply) and returns the ready tunnel.
// All round trips complete before the caller writes a single application byte.
func DialSequential(proxyAddr, user, pass, dst string, dial DialFunc) (net.Conn, error) {
	cl, _ := socks5.NewClient(proxyAddr, user, pass, 0, 0)
	cl.DialTCP = func(network, laddr, raddr string) (net.Conn, error) { return dial() }
	return cl.Dial("tcp", dst)
}

// DialPipelined coalesces greeting + [auth] + CONNECT into one write, then
// reads and validates the replies before returning the ready tunnel — saving
// the pre-request round trips but still paying one client<->proxy RTT for the
// replies before the caller may write application data.
func DialPipelined(proxyAddr, user, pass, dst string, dial DialFunc) (net.Conn, error) {
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

// readHandshakeReplies reads and validates the method / [auth] / CONNECT
// replies in order, mirroring Conn.readReplies for the comparison path.
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

// roundTrip writes payload then reads len(payload) echoed bytes back, returning
// them — a small helper for the lab's request/response exchange.
func roundTrip(conn net.Conn, payload []byte) ([]byte, error) {
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return nil, err
	}
	if !bytes.Equal(got, payload) {
		return got, fmt.Errorf("echo mismatch: sent %q got %q", payload, got)
	}
	return got, nil
}
