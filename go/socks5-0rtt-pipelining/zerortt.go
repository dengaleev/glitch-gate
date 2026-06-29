// Package zerortt implements "0-RTT data pipelining" for SOCKS5 CONNECT over
// github.com/txthinking/socks5's wire primitives: the handshake is deferred and
// sent together with the application's first payload in one write, before any
// reply is read, so the proxy forwards that payload the instant the
// proxy->target connection opens — saving the round trip ordinary pipelining
// spends waiting for the CONNECT reply. With FastOpen the same write rides in
// the TCP SYN, removing the proxy TCP handshake too.
//
// It needs no server change: any RFC 1928 server that reads each handshake
// message with io.ReadFull on the raw conn and relays from that same conn
// (txthinking's DefaultHandle does) forwards the trailing early bytes once it
// dials the target.
//
// The payload leaves before the auth/CONNECT result is known, so a rejection
// surfaces only on the first Read after the data was already "sent". Like TLS
// 1.3 0-RTT this is opt-in and fit only for a replay-safe first payload — a TLS
// ClientHello (an HTTPS target) being the ideal case.
package zerortt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	tfo "github.com/database64128/tfo-go/v2"
	"github.com/txthinking/socks5"
)

// DefaultClientDataWait is the window the first Read gives a concurrent first
// Write to supply early data before flushing the handshake alone — long enough
// to win the goroutine race (net/http reads and writes from separate
// goroutines), short of a real RTT. Mirrors Outline SDK's ClientDataWait.
const DefaultClientDataWait = 10 * time.Millisecond

// ErrConnectRejected wraps a non-success CONNECT reply. Since 0-RTT sends the
// payload before the reply is known, callers detect a rejected optimistic send
// with errors.Is to decide whether to retry on a fresh connection. (Other
// handshake-phase failures are wrapped too, so prefer errors.Is over ==.)
var ErrConnectRejected = errors.New("zerortt: proxy rejected CONNECT")

// Dialer dials SOCKS5 CONNECT tunnels that pipeline the first application
// payload with the handshake. ProxyAddress must be set; it is otherwise usable
// as its zero value and safe for concurrent use. DialContext matches
// x/net/proxy.ContextDialer and http.Transport.DialContext.
type Dialer struct {
	// ProxyAddress is the SOCKS5 proxy, as "host:port".
	ProxyAddress string

	// Username and Password select RFC 1929 user/pass auth only when both are
	// set; leaving either empty is no-auth.
	Username string
	Password string

	// FastOpen carries the handshake and first payload in the TCP SYN (TCP Fast
	// Open), removing the proxy TCP-handshake round trip; it falls back to a
	// normal connection when unavailable. Because the SYN must carry the first
	// payload, a FastOpen connection is dialed lazily on first I/O (see Conn).
	FastOpen bool

	// ClientDataWait bounds the first Read's wait for a concurrent first Write
	// (see DefaultClientDataWait). Zero means the default; negative disables it.
	ClientDataWait time.Duration

	// NetDialer is the base dialer for the proxy socket. With FastOpen, set its
	// Timeout to bound the lazy connect, which a Conn deadline cannot reach.
	NetDialer *net.Dialer

	// dialProxy is a test seam for wrapping the (non-FastOpen) proxy socket.
	dialProxy func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerFromURL builds a Dialer from a socks5:// or socks5h:// proxy URL (port
// defaults to 1080). User/pass auth needs both credentials present. The result
// can be further configured (FastOpen, ClientDataWait, NetDialer) before use.
func DialerFromURL(rawURL string) (*Dialer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("zerortt: parse proxy URL %q: %w", rawURL, err)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("zerortt: unsupported proxy scheme %q (want socks5:// or socks5h://)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("zerortt: proxy URL %q has no host", rawURL)
	}
	port := u.Port()
	if port == "" {
		port = "1080"
	}
	pass, _ := u.User.Password()
	return &Dialer{
		ProxyAddress: net.JoinHostPort(u.Hostname(), port),
		Username:     u.User.Username(),
		Password:     pass,
	}, nil
}

func (d *Dialer) clientDataWait() time.Duration {
	switch {
	case d.ClientDataWait == 0:
		return DefaultClientDataWait
	case d.ClientDataWait < 0:
		return 0
	default:
		return d.ClientDataWait
	}
}

// Dial is DialContext with context.Background.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext prepares a deferred 0-RTT CONNECT tunnel to address (resolved by
// the proxy); network must be a TCP variant. No bytes reach the proxy until the
// returned Conn's first I/O. A non-FastOpen dialer connects eagerly here so the
// TCP handshake overlaps request preparation; FastOpen defers the connect so the
// handshake+payload can ride in the SYN.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("zerortt: unsupported network %q (SOCKS5 CONNECT is TCP only)", network)
	}
	if d.ProxyAddress == "" {
		return nil, errors.New("zerortt: empty ProxyAddress")
	}

	method := socks5.MethodNone
	if d.Username != "" && d.Password != "" {
		method = socks5.MethodUsernamePassword
	}
	pre, err := buildHandshake(method, d.Username, d.Password, address)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		method:         method,
		pre:            pre,
		clientDataWait: d.clientDataWait(),
		flushedCh:      make(chan struct{}),
	}

	base := d.NetDialer
	if base == nil {
		base = &net.Dialer{}
	}

	if d.FastOpen {
		// net/http cancels the dial ctx before this lazy connect runs, so root it
		// in a Conn-lifecycle context that Close cancels and that inherits only
		// the caller's deadline. NetDialer.Timeout bounds it too.
		td := &tfo.Dialer{Dialer: *base, Fallback: true}
		var connCtx context.Context
		if dl, ok := ctx.Deadline(); ok {
			connCtx, c.connCancel = context.WithDeadline(context.Background(), dl)
		} else {
			connCtx, c.connCancel = context.WithCancel(context.Background())
		}
		c.connect = func(initial []byte) (net.Conn, int, error) {
			conn, err := td.DialContext(connCtx, "tcp", d.ProxyAddress, initial)
			if err != nil {
				return nil, 0, fmt.Errorf("zerortt: fast-open dial proxy %s: %w", d.ProxyAddress, err)
			}
			return conn, len(initial), nil
		}
		return c, nil
	}

	dialProxy := d.dialProxy
	if dialProxy == nil {
		dialProxy = base.DialContext
	}
	raw, err := dialProxy(ctx, "tcp", d.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("zerortt: dial proxy %s: %w", d.ProxyAddress, err)
	}
	c.raw = raw
	c.connect = func(initial []byte) (net.Conn, int, error) {
		n, err := raw.Write(initial)
		if err == nil && n < len(initial) {
			err = io.ErrShortWrite // a truncated handshake must not look like success
		}
		return raw, n, err
	}
	return c, nil
}

// Conn is the net.Conn returned by Dialer. The handshake is deferred: it rides
// with the first Write as early data, or — if the caller reads first
// (server-speaks-first protocols) — is flushed alone on the first Read,
// degrading to plain handshake pipelining; replies are validated lazily on the
// first Read. A FastOpen Conn connects on first I/O, so LocalAddr/RemoteAddr are
// nil and Conn deadlines don't reach the connect until then.
type Conn struct {
	method byte
	pre    []byte // assembled handshake: greeting || [auth] || CONNECT

	clientDataWait time.Duration

	// connect delivers initial to the proxy and reports bytes accepted: the
	// eager path writes to the open socket, FastOpen dials with initial as SYN
	// data.
	connect func(initial []byte) (net.Conn, int, error)

	// connCancel aborts the FastOpen lazy connect; Close calls it without wmu so
	// it can interrupt a blocked dial. Idempotent; nil on the eager path.
	connCancel func()

	// wmu and rmu are never held simultaneously, so their order is unconstrained.
	wmu       sync.Mutex    // serializes writes and guards the one-time flush
	raw       net.Conn      // pre-set when eager, nil until flush when FastOpen
	flushed   bool          // handshake bytes have been written
	flushErr  error         // result of the handshake write/connect
	flushedCh chan struct{} // closed once flushed, to wake a waiting Read

	rmu      sync.Mutex // guards the one-time reply validation
	replied  bool
	replyErr error
}

var _ net.Conn = (*Conn)(nil)

// buildHandshake collects greeting || [auth] || CONNECT into one buffer — the
// bytes Negotiate()+Request() would send, just not split across writes.
func buildHandshake(method byte, user, pass, dst string) ([]byte, error) {
	atyp, addr, port, err := socks5.ParseAddress(dst)
	if err != nil {
		return nil, fmt.Errorf("zerortt: parse destination %q: %w", dst, err)
	}
	if atyp == socks5.ATYPDomain {
		addr = addr[1:] // ParseAddress length-prefixes the domain; NewRequest re-adds it
	}
	var buf bytes.Buffer // writes to a bytes.Buffer cannot fail
	_, _ = socks5.NewNegotiationRequest([]byte{method}).WriteTo(&buf)
	if method == socks5.MethodUsernamePassword {
		_, _ = socks5.NewUserPassNegotiationRequest([]byte(user), []byte(pass)).WriteTo(&buf)
	}
	_, _ = socks5.NewRequest(socks5.CmdConnect, atyp, addr, port).WriteTo(&buf)
	return buf.Bytes(), nil
}

// Write sends application data; the first Write coalesces the handshake in front
// of p. The returned count covers only p, never the prepended handshake.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.flush(p)
}

// Flush sends the handshake with no early data (plain handshake pipelining), for
// a caller with no first payload to coalesce. No-op once anything has flushed.
func (c *Conn) Flush() error {
	_, err := c.flush(nil)
	return err
}

// flush performs the one-time handshake delivery (optionally with early data
// appended) and returns the count of early bytes accepted. Later calls forward
// to the conn, or replay the handshake error if delivery failed.
func (c *Conn) flush(early []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.flushed {
		if c.flushErr != nil || len(early) == 0 {
			return 0, c.flushErr
		}
		return c.raw.Write(early)
	}
	c.flushed = true
	defer close(c.flushedCh) // runs before wmu.Unlock; wakes a waiting Read

	payload := c.pre
	if len(early) > 0 {
		payload = make([]byte, 0, len(c.pre)+len(early))
		payload = append(payload, c.pre...)
		payload = append(payload, early...)
	}

	conn, n, err := c.connect(payload)
	if c.connCancel != nil {
		c.connCancel() // connect finished; release the FastOpen connect context
	}
	c.raw = conn
	c.flushErr = err
	if err != nil {
		return 0, err
	}

	// Report only application bytes; on success the whole payload landed.
	return min(max(n-len(c.pre), 0), len(early)), nil
}

func (c *Conn) isFlushed() bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.flushed
}

// Read returns target data, first flushing the handshake (alone, if nothing has
// been written) and validating the method/[auth]/CONNECT replies once. Replies
// are read with exact-length io.ReadFull, so target bytes coalesced into the
// same segment survive for the next read.
func (c *Conn) Read(b []byte) (int, error) {
	// Give a concurrent first Write its ClientDataWait window to coalesce early
	// data; otherwise net/http's read loop could flush a bare handshake and lose
	// the 0-RTT (Outline SDK does the same).
	if c.clientDataWait > 0 && !c.isFlushed() {
		t := time.NewTimer(c.clientDataWait)
		select {
		case <-c.flushedCh:
		case <-t.C:
		}
		t.Stop()
	}
	if _, err := c.flush(nil); err != nil {
		return 0, err
	}
	if err := c.ensureReplies(); err != nil {
		return 0, err
	}
	// Safe without wmu: the flush(nil) above synchronized c.raw through wmu.
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
		return fmt.Errorf("zerortt: read method reply: %w", err)
	}
	if nrep.Method != c.method {
		return fmt.Errorf("zerortt: server selected method 0x%02x, expected 0x%02x", nrep.Method, c.method)
	}
	if c.method == socks5.MethodUsernamePassword {
		arep, err := socks5.NewUserPassNegotiationReplyFrom(c.raw)
		if err != nil {
			return fmt.Errorf("zerortt: read auth reply: %w", err)
		}
		if arep.Status != socks5.UserPassStatusSuccess {
			return fmt.Errorf("zerortt: authenticate: %w", socks5.ErrUserPassAuth)
		}
	}
	rep, err := socks5.NewReplyFrom(c.raw)
	if err != nil {
		return fmt.Errorf("zerortt: read connect reply: %w", err)
	}
	if rep.Rep != socks5.RepSuccess {
		return fmt.Errorf("%w (rep=0x%02x)", ErrConnectRejected, rep.Rep)
	}
	return nil
}

// Close closes the proxy connection, first canceling any in-flight FastOpen
// connect (without wmu, so it can interrupt a blocked dial). A FastOpen Conn
// that never flushed has nothing to close.
func (c *Conn) Close() error {
	if c.connCancel != nil {
		c.connCancel()
	}
	c.wmu.Lock()
	raw := c.raw
	c.wmu.Unlock()
	if raw == nil {
		return nil
	}
	return raw.Close()
}

func (c *Conn) rawConn() net.Conn {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.raw
}

// LocalAddr reports the proxy socket's local address (nil before a FastOpen Conn connects).
func (c *Conn) LocalAddr() net.Addr {
	if r := c.rawConn(); r != nil {
		return r.LocalAddr()
	}
	return nil
}

// RemoteAddr reports the proxy socket's remote address (nil before a FastOpen Conn connects).
func (c *Conn) RemoteAddr() net.Addr {
	if r := c.rawConn(); r != nil {
		return r.RemoteAddr()
	}
	return nil
}

// SetDeadline sets the proxy socket's deadlines. It is a no-op on a FastOpen Conn
// before first I/O (no socket yet) — bound the connect with NetDialer.Timeout.
func (c *Conn) SetDeadline(t time.Time) error {
	if r := c.rawConn(); r != nil {
		return r.SetDeadline(t)
	}
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if r := c.rawConn(); r != nil {
		return r.SetReadDeadline(t)
	}
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if r := c.rawConn(); r != nil {
		return r.SetWriteDeadline(t)
	}
	return nil
}
