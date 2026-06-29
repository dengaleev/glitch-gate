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
// With FastOpen, the coalesced handshake+payload is handed to the proxy in the
// TCP SYN (TCP Fast Open), removing the proxy TCP handshake round trip too and
// approaching literal zero added round trips before the first byte is on the
// wire.
//
// Safety: the early bytes leave the client before the auth/CONNECT result is
// known, so a rejected CONNECT, failed auth, or reset surfaces as an error on
// the first Read after the application has already "sent" data. Like TLS 1.3
// 0-RTT, this is opt-in and only appropriate for a replay-safe first payload —
// a TLS ClientHello (i.e. an HTTPS target) being the ideal case.
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

// DefaultClientDataWait is how long the first Read waits for a concurrent first
// Write to supply early data before flushing the handshake alone. It mirrors
// Outline SDK's Shadowsocks ClientDataWait: longer than any reasonable
// inter-goroutine handoff, shorter than a real network RTT.
const DefaultClientDataWait = 10 * time.Millisecond

// ErrConnectRejected is returned, wrapped, when the proxy answers the CONNECT
// with a non-success reply. Because 0-RTT pipelining sends the first payload
// before this reply is known, a caller that needs to detect a rejected
// optimistic send (to decide whether to retry on a fresh connection) can test
// for it with errors.Is. Handshake-phase failures generally surface as wrapped
// "zerortt:" errors — use errors.Is rather than == (e.g. errors.Is(err, io.EOF)).
var ErrConnectRejected = errors.New("zerortt: proxy rejected CONNECT")

// Dialer establishes SOCKS5 CONNECT tunnels that pipeline the first application
// payload with the handshake (0-RTT data pipelining). The zero value is not
// usable; ProxyAddress must be set. A Dialer is safe for concurrent use.
//
// It implements the de-facto golang.org/x/net/proxy.ContextDialer shape
// (DialContext) and plugs straight into http.Transport.DialContext.
type Dialer struct {
	// ProxyAddress is the SOCKS5 proxy, as "host:port".
	ProxyAddress string

	// Username and Password select RFC 1929 user/pass auth when both are set;
	// leaving either empty selects no-auth.
	Username string
	Password string

	// FastOpen uses TCP Fast Open to carry the SOCKS5 handshake and the first
	// application payload in the TCP SYN, removing the proxy TCP-handshake round
	// trip. It requires OS support on both ends and a TFO-capable proxy; when
	// unavailable it transparently falls back to a normal connection. Because
	// the SYN must carry the first payload, a FastOpen connection is dialed
	// lazily on the first Write/Read rather than at DialContext time (see Conn).
	FastOpen bool

	// ClientDataWait bounds how long the first Read blocks for a concurrent
	// first Write to provide early data before flushing the handshake alone.
	// Zero uses DefaultClientDataWait; a negative value disables the wait
	// (flush immediately on a read-first caller).
	ClientDataWait time.Duration

	// NetDialer is the base dialer for the proxy socket (timeouts, Control,
	// local address). When nil, a zero-value net.Dialer is used. With FastOpen,
	// set NetDialer.Timeout to bound the lazily-performed connect, since a
	// deadline set on the Conn before its first I/O cannot reach that connect.
	NetDialer *net.Dialer

	// dialProxy is a test seam: when non-nil it creates the (non-FastOpen) proxy
	// socket instead of NetDialer, letting tests wrap the conn with shims.
	dialProxy func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerFromURL builds a Dialer from a SOCKS5 proxy URL such as
// "socks5://user:pass@host:1080" (socks5h:// is also accepted; the destination
// is always resolved by the proxy regardless). The port defaults to 1080.
// User/pass auth is selected only when both a username and a password are
// present (a username with an empty password connects with no auth). The
// returned Dialer can be further configured (FastOpen, ClientDataWait,
// NetDialer) before use.
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

// DialContext prepares a 0-RTT SOCKS5 CONNECT tunnel to address (a "host:port"
// destination the proxy will resolve). network must name a TCP variant. The
// returned Conn defers the SOCKS5 handshake to its first I/O, so no bytes reach
// the proxy until then; for a non-FastOpen dialer the proxy TCP connection is
// established eagerly here, while a FastOpen dialer defers the connect to the
// first write so the handshake+payload can ride in the SYN.
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
		// Lazy connect: the SOCKS5 handshake + first payload ride in the SYN, so
		// the actual connect happens on first flush, carrying those bytes. The
		// caller's dial ctx is canceled by net/http once DialContext returns
		// (before this connect runs), so the connect is rooted in a fresh,
		// Conn-lifecycle context that Close cancels and that inherits only the
		// caller's deadline (not its premature cancellation). NetDialer.Timeout
		// bounds it too.
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

	// Eager connect: conventional behavior. The TCP handshake overlaps with the
	// application preparing its first payload; the handshake+payload then go out
	// on the first Write.
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

// Conn is a deferred-handshake SOCKS5 CONNECT connection returned by Dialer. It
// implements net.Conn. The SOCKS5 handshake is not performed at dial time; it
// is buffered and flushed, prepended to the application's first Write (carrying
// it as 0-RTT early data) or — if the application reads first, as
// server-speaks-first protocols do — flushed alone on the first Read, degrading
// gracefully to plain handshake pipelining. The handshake replies are validated
// lazily on the first Read.
//
// With a FastOpen dialer the underlying proxy connection is created on the
// first flush (so the handshake+payload can ride in the SYN); until then
// LocalAddr/RemoteAddr report nil and a deadline set on the Conn does not reach
// the connect (bound it with Dialer.NetDialer.Timeout instead).
type Conn struct {
	method byte
	pre    []byte // assembled handshake: greeting || [auth] || CONNECT

	clientDataWait time.Duration

	// connect delivers initial to the proxy and returns the live connection and
	// the number of initial bytes accepted. For an eager (non-FastOpen) dialer
	// it writes to the already-established socket; for FastOpen it dials with
	// initial as SYN data. Set once by Dialer.DialContext.
	connect func(initial []byte) (net.Conn, int, error)

	// connCancel cancels the FastOpen lazy connect (nil for the eager path).
	// Set once at construction, so Close can call it without holding wmu to
	// abort an in-flight SYN-data dial. Idempotent.
	connCancel func()

	// wmu and rmu are never held simultaneously; their acquisition order is
	// therefore unconstrained.
	wmu       sync.Mutex    // serializes writes and guards the one-time flush
	raw       net.Conn      // live proxy conn; pre-set when eager, nil until flush when FastOpen
	flushed   bool          // handshake bytes have been written
	flushErr  error         // result of the handshake write/connect
	flushedCh chan struct{} // closed once, after the handshake bytes are written

	rmu      sync.Mutex // guards the one-time reply validation
	replied  bool
	replyErr error
}

var _ net.Conn = (*Conn)(nil)

// buildHandshake assembles the exact wire bytes for greeting || [auth] ||
// CONNECT using txthinking's primitives — the same assembly the regular client
// performs across Negotiate()+Request(), just collected into one buffer.
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

// flush performs the one-time handshake delivery, optionally with early
// application data appended, and returns how many bytes of early were accepted.
// After the first flush it forwards early to the raw conn (unless the handshake
// delivery itself failed, in which case that error is returned without touching
// the wire again).
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

	// Report only application bytes. On success the whole payload is delivered,
	// so appN == len(early).
	appN := n - len(c.pre)
	if appN < 0 {
		appN = 0
	} else if appN > len(early) {
		appN = len(early)
	}
	return appN, nil
}

func (c *Conn) isFlushed() bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.flushed
}

// Read returns tunneled data from the target. It first guarantees the handshake
// is on the wire (flushing it alone if the application has not written yet) and
// then, once, reads and validates the method / [auth] / CONNECT replies in
// order before surfacing any target bytes. Because the replies are read with
// io.ReadFull of their exact lengths, target data the proxy may have coalesced
// into the same TCP segment is left intact for this and subsequent reads.
func (c *Conn) Read(b []byte) (int, error) {
	// Give a concurrent first Write a brief window to supply early data before
	// we flush the handshake alone. Without this, net/http's readLoop racing
	// its writeLoop could flush a bare handshake and silently lose the 0-RTT
	// coalescing. (Outline SDK uses the same bounded-wait trick.)
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

// Close closes the underlying proxy connection. For a FastOpen Conn it first
// cancels any in-flight lazy connect (without taking wmu, so it can interrupt a
// first flush that is blocked dialing); a FastOpen Conn that never reached its
// first flush then has no connection to close. Calling the underlying Close
// more than once returns that conn's error on the later calls.
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

// LocalAddr reports the proxy socket's local address, or nil before a FastOpen
// Conn has connected.
func (c *Conn) LocalAddr() net.Addr {
	if r := c.rawConn(); r != nil {
		return r.LocalAddr()
	}
	return nil
}

// RemoteAddr reports the proxy socket's remote address, or nil before a FastOpen
// Conn has connected.
func (c *Conn) RemoteAddr() net.Addr {
	if r := c.rawConn(); r != nil {
		return r.RemoteAddr()
	}
	return nil
}

// SetDeadline sets read and write deadlines on the proxy socket. On a FastOpen
// Conn before its first I/O there is no socket yet, so the call is a no-op;
// bound the lazily-performed connect with Dialer.NetDialer.Timeout instead.
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
