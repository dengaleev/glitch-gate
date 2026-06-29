// Package zerortt implements "0-RTT data pipelining" for SOCKS5 CONNECT over
// github.com/txthinking/socks5's wire primitives.
//
// Ordinary handshake pipelining coalesces the SOCKS5 greeting, optional
// user/pass auth, and the CONNECT request into a single write, then waits for
// the CONNECT reply before the application sends its first byte. 0-RTT data
// pipelining goes one step further: it defers the handshake until the
// application's first Write and sends the handshake *and* that first payload in
// one write — before any reply is read — the way TLS 1.3 early data and TCP
// Fast Open carry application bytes before the peer confirms. The replies are
// read and validated lazily on the first Read.
//
// This is purely a client-side optimization. It needs no SOCKS5 protocol
// extension and no server change: any RFC-1928 server that parses each
// handshake message with io.ReadFull on the raw connection (no buffered
// read-ahead it later discards) and relays the client->target direction from
// that same connection will forward the early bytes to the target as soon as
// the proxy->target connection opens. txthinking/socks5's own DefaultHandle is
// exactly such a server.
//
// Safety: the early bytes leave the client before the auth/CONNECT result is
// known, so a rejected CONNECT, failed auth, or reset surfaces as an error on
// the first Read after the application has already "sent" data. Like TLS 1.3
// 0-RTT, this is opt-in and only appropriate for a replay-safe first payload —
// a TLS ClientHello (i.e. an HTTPS target) being the ideal case.
package zerortt

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/txthinking/socks5"
)

// Conn is a deferred-handshake SOCKS5 CONNECT connection. It implements
// net.Conn. The SOCKS5 handshake is not performed at dial time; it is buffered
// and flushed, prepended to the application's first Write (carrying it as 0-RTT
// early data) or — if the application reads first, as server-speaks-first
// protocols do — flushed alone on the first Read, degrading gracefully to
// plain handshake pipelining. The handshake replies are validated lazily on
// the first Read.
type Conn struct {
	raw    net.Conn
	method byte
	pre    []byte // assembled handshake: greeting || [auth] || CONNECT

	wmu     sync.Mutex // serializes writes and guards the one-time flush
	flushed bool

	rmu      sync.Mutex // guards the one-time reply validation
	replied  bool
	replyErr error
}

var _ net.Conn = (*Conn)(nil)

// Dial opens a connection to the SOCKS5 proxy and prepares (but does not send)
// a CONNECT to dst. Pass empty user and pass for no-auth; supplying both
// selects RFC 1929 user/pass auth. dialProxy, when non-nil, creates the proxy
// socket (use it to inject a TCP Fast Open dialer, set socket options, or shim
// in latency for testing); when nil, net.Dial("tcp", proxyAddr) is used.
//
// No bytes reach the proxy until the first Write/Read/Flush on the returned
// Conn, so the round trip that carries the handshake is shared with the first
// application payload.
func Dial(proxyAddr, user, pass, dst string, dialProxy func() (net.Conn, error)) (*Conn, error) {
	method := socks5.MethodNone
	if user != "" && pass != "" {
		method = socks5.MethodUsernamePassword
	}
	pre, err := buildHandshake(method, user, pass, dst)
	if err != nil {
		return nil, err
	}
	if dialProxy == nil {
		dialProxy = func() (net.Conn, error) { return net.Dial("tcp", proxyAddr) }
	}
	raw, err := dialProxy()
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	return &Conn{raw: raw, method: method, pre: pre}, nil
}

// buildHandshake assembles the exact wire bytes for greeting || [auth] ||
// CONNECT using txthinking's primitives — the same assembly the regular client
// performs across Negotiate()+Request(), just collected into one buffer.
func buildHandshake(method byte, user, pass, dst string) ([]byte, error) {
	atyp, addr, port, err := socks5.ParseAddress(dst)
	if err != nil {
		return nil, fmt.Errorf("parse dst %q: %w", dst, err)
	}
	if atyp == socks5.ATYPDomain {
		addr = addr[1:] // ParseAddress length-prefixes the domain; NewRequest re-adds it
	}
	var buf bytes.Buffer
	_, _ = socks5.NewNegotiationRequest([]byte{method}).WriteTo(&buf)
	if method == socks5.MethodUsernamePassword {
		_, _ = socks5.NewUserPassNegotiationRequest([]byte(user), []byte(pass)).WriteTo(&buf)
	}
	_, _ = socks5.NewRequest(socks5.CmdConnect, atyp, addr, port).WriteTo(&buf)
	return buf.Bytes(), nil
}

// Write sends application data. The first Write flushes the buffered handshake
// in front of p in a single underlying write (the 0-RTT path); the returned
// count is the number of bytes of p written, never including the handshake.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.flush(p)
}

// Flush forces the handshake onto the wire with no early data, committing to
// plain handshake pipelining. It is a no-op once anything has been flushed.
// Useful when the caller has no first payload to coalesce but wants to start
// the handshake (e.g. before blocking on Read).
func (c *Conn) Flush() error {
	_, err := c.flush(nil)
	return err
}

// flush writes the handshake exactly once, optionally with early application
// data appended, and returns how many bytes of early were written. After the
// first flush it simply forwards early to the raw conn.
func (c *Conn) flush(early []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.flushed {
		if len(early) == 0 {
			return 0, nil
		}
		return c.raw.Write(early)
	}
	c.flushed = true

	if len(early) == 0 {
		_, err := c.raw.Write(c.pre)
		return 0, err
	}

	// One write: handshake immediately followed by the first payload.
	buf := make([]byte, 0, len(c.pre)+len(early))
	buf = append(buf, c.pre...)
	buf = append(buf, early...)
	n, err := c.raw.Write(buf)

	// Report only application bytes. A net.Conn Write blocks until all bytes
	// are sent or it errors, so on success n == len(buf) and appN == len(early).
	appN := n - len(c.pre)
	if appN < 0 {
		appN = 0
	} else if appN > len(early) {
		appN = len(early)
	}
	return appN, err
}

// Read returns tunneled data from the target. It first guarantees the
// handshake is on the wire (flushing it alone if the application has not
// written yet) and then, once, reads and validates the method / [auth] /
// CONNECT replies in order before surfacing any target bytes. Because the
// replies are read with io.ReadFull of their exact lengths, target data the
// proxy may have coalesced into the same TCP segment is left intact for this
// and subsequent reads.
func (c *Conn) Read(b []byte) (int, error) {
	if _, err := c.flush(nil); err != nil {
		return 0, err
	}
	if err := c.ensureReplies(); err != nil {
		return 0, err
	}
	return c.raw.Read(b)
}

func (c *Conn) ensureReplies() error {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.replied {
		return c.replyErr
	}
	c.replied = true
	c.replyErr = c.readReplies()
	return c.replyErr
}

func (c *Conn) readReplies() error {
	nrep, err := socks5.NewNegotiationReplyFrom(c.raw)
	if err != nil {
		return fmt.Errorf("read method reply: %w", err)
	}
	if nrep.Method != c.method {
		return fmt.Errorf("server selected method 0x%02x, expected 0x%02x", nrep.Method, c.method)
	}
	if c.method == socks5.MethodUsernamePassword {
		arep, err := socks5.NewUserPassNegotiationReplyFrom(c.raw)
		if err != nil {
			return fmt.Errorf("read auth reply: %w", err)
		}
		if arep.Status != socks5.UserPassStatusSuccess {
			return fmt.Errorf("authenticate: %w", socks5.ErrUserPassAuth)
		}
	}
	rep, err := socks5.NewReplyFrom(c.raw)
	if err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if rep.Rep != socks5.RepSuccess {
		return fmt.Errorf("connect rejected (rep=0x%02x)", rep.Rep)
	}
	return nil
}

// Close closes the underlying proxy connection. If nothing was ever flushed the
// proxy simply sees a connection that opened and closed without a handshake.
func (c *Conn) Close() error { return c.raw.Close() }

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
