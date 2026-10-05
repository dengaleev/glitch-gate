package socks0_test

// The shared test harness: fake proxies built on package wire, in-memory and
// recording conns, and small runners.

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	modes        = []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly}
	errTest      = errors.New("test error")
	defaultBound = mustAddr("192.0.2.1:1080")
	upAuth       = socks0.UserPass{Username: "user", Password: "S3CRETpw"}
	// hsNoAuth is the client's pipelined handshake for example.com:80 without auth.
	hsNoAuth = slices.Concat([]byte{5, 1, 0}, must(wire.AppendRequest(nil, wire.CmdConnect, mustAddr("example.com:80"))))
	// goodReplies are the server's no-auth replies with BND 192.0.2.1:1080.
	goodReplies = serverMsgs(false, "192.0.2.1:1080")
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func mustAddr(s string) wire.Addr { return must(wire.ParseAddr(s)) }

func reply(rep wire.Reply, bound string) []byte {
	return must(wire.AppendReply(nil, rep, mustAddr(bound)))
}

// serverMsgs is a successful method selection, auth status if auth, and reply.
func serverMsgs(auth bool, bound string) []byte {
	b := []byte{5, 0}
	if auth {
		b = []byte{5, 2, 1, 0}
	}
	return append(b, reply(0, bound)...)
}

// listen serves handle on 127.0.0.1 until the test ends.
func listen(t testing.TB, handle func(net.Conn)) string { return listenOn(t, "tcp4", handle) }

// listenOn serves handle on loopback: "tcp4" (127.0.0.1) or "tcp6" ([::1]).
func listenOn(t testing.TB, network string, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen(network, map[string]string{"tcp4": "127.0.0.1:0", "tcp6": "[::1]:0"}[network])
	if err != nil {
		t.Fatal(err)
	}
	return serve(t, ln, handle)
}

// serve runs handle for each conn ln accepts until the test ends.
func serve(t testing.TB, ln net.Listener, handle func(net.Conn)) string {
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { defer c.Close(); handle(c) })
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

// proxy is a scriptable SOCKS5 server.
type proxy struct {
	method   *wire.Method // selected; nil selects the first offered
	status   uint8        // RFC 1929 status
	rep      wire.Reply
	bound    wire.Addr      // zero: 192.0.2.1:1080
	tail     []byte         // sent in the same write as the reply
	coalesce bool           // read the whole pipelined handshake, then reply in one write
	after    func(net.Conn) // runs after a successful reply; nil echoes
	got      chan request   // receives what the client sent, if non-nil
	// handle, if set, answers the request instead of rep, bound, tail and after.
	handle func(c net.Conn, cmd wire.Command, dst wire.Addr)
}

type request struct {
	methods    []wire.Method
	user, pass string
	cmd        wire.Command
	target     wire.Addr
}

func (p proxy) serve(c net.Conn) {
	var (
		req  request
		out  []byte
		err  error
		sent bool
	)
	defer func() { // a failed negotiation reports what was offered
		if p.got != nil && !sent && req.methods != nil {
			p.got <- req
		}
	}()
	flush := func() {
		if !p.coalesce {
			c.Write(out)
			out = out[:0]
		}
	}
	if req.methods, err = wire.ReadGreeting(c); err != nil {
		return
	}
	m := cmp.Or(p.method, &req.methods[0])
	out = wire.AppendMethodSelection(out, *m)
	if !slices.Contains(req.methods, *m) || *m != wire.MethodNoAuth && *m != wire.MethodUserPass {
		c.Write(out)
		return
	}
	flush()
	if *m == wire.MethodUserPass {
		u, pw, err := wire.ReadUserPass(c)
		if err != nil {
			return
		}
		req.user, req.pass = string(u), string(pw)
		if out = wire.AppendUserPassStatus(out, p.status); p.status != 0 {
			c.Write(out)
			return
		}
		flush()
	}
	cmd, dst, err := wire.ReadRequest(c)
	if err != nil {
		return
	}
	if req.cmd, req.target, sent = cmd, dst, true; p.got != nil {
		p.got <- req
	}
	if p.handle != nil {
		if len(out) > 0 {
			c.Write(out)
		}
		p.handle(c, cmd, dst)
		return
	}
	out, _ = wire.AppendReply(out, p.rep, cmp.Or(p.bound, defaultBound))
	c.Write(append(out, p.tail...))
	switch {
	case p.rep != wire.ReplySucceeded:
	case p.after != nil:
		p.after(c)
	default:
		io.Copy(c, c)
	}
}

// answer is a proxy answering any request with resp and closing, as Tor does
// for RESOLVE; with hold, or a nil resp, it keeps the conn open.
func answer(resp []byte, got chan request, hold bool) func(net.Conn) {
	return proxy{got: got, handle: func(c net.Conn, _ wire.Command, _ wire.Addr) {
		c.Write(resp)
		if hold || resp == nil {
			io.Copy(io.Discard, c)
		}
	}}.serve
}

// bind5 is a proxy running script after a BIND request.
func bind5(script func(c net.Conn)) func(net.Conn) {
	return proxy{handle: func(c net.Conn, cmd wire.Command, _ wire.Addr) {
		if cmd == wire.CmdBind {
			script(c)
		}
	}}.serve
}

// scripted answers resp to the first bytes, then half-closes unless silent.
func scripted(resp []byte, silent bool) func(net.Conn) {
	return func(c net.Conn) {
		if _, err := c.Read(make([]byte, 1024)); err != nil {
			return
		}
		c.Write(resp)
		if !silent {
			c.(*net.TCPConn).CloseWrite()
		}
		io.Copy(io.Discard, c)
	}
}

// bindProxy serves BIND: one peer on loopback, two replies, then relays.
type bindProxy struct {
	bnd        func(ln netip.AddrPort) wire.Addr // BND of reply 1; nil: the listener's address
	rep1, rep2 wire.Reply
	eof        bool           // close instead of reply 2, once the peer connected
	peerFirst  int            // bytes the peer sends to read before reply 2, sent with it in one write
	got        chan wire.Addr // receives DST, if not nil
}

func (p bindProxy) serve(c net.Conn) {
	proxy{handle: func(c net.Conn, cmd wire.Command, dst wire.Addr) {
		if cmd != wire.CmdBind {
			return
		}
		if p.got != nil {
			p.got <- dst
		}
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer ln.Close()
		bnd := wire.AddrFromAddrPort(ln.Addr().(*net.TCPAddr).AddrPort())
		if p.bnd != nil {
			bnd = p.bnd(ln.Addr().(*net.TCPAddr).AddrPort())
		}
		c.Write(must(wire.AppendReply(nil, p.rep1, bnd)))
		if p.rep1 != 0 {
			return
		}
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(300 * time.Millisecond)) // the client may give up
		peer, err := ln.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		if p.eof {
			return
		}
		first := make([]byte, p.peerFirst)
		if _, err := io.ReadFull(peer, first); err != nil {
			return
		}
		b, _ := wire.AppendReply(nil, p.rep2, wire.AddrFromAddrPort(peer.RemoteAddr().(*net.TCPAddr).AddrPort()))
		c.Write(append(b, first...))
		if p.rep2 != 0 {
			return
		}
		go func() { io.Copy(peer, c); peer.(*net.TCPConn).CloseWrite() }()
		io.Copy(c, peer)
	}}.serve(c)
}

type request4 struct {
	cmd  wire.Command
	addr wire.Addr
	user string
}

// proxy4 is a SOCKS4 server: CONNECT echoes; BIND's reply 1 has DSTIP 0 ("this proxy", per spec).
type proxy4 struct {
	cd  wire.Reply // zero: granted
	raw []byte     // if set, the whole answer
	got chan request4
}

func (p proxy4) serve(c net.Conn) {
	cmd, addr, user, err := wire.ReadRequest4(c)
	if err != nil {
		return
	}
	if p.got != nil {
		p.got <- request4{cmd, addr, string(user)}
	}
	if p.raw != nil {
		c.Write(p.raw)
		return
	}
	cd := cmp.Or(p.cd, wire.Reply4Granted)
	if cmd != wire.CmdBind {
		c.Write(must(wire.AppendReply4(nil, cd, wire.Addr{})))
		if cd == wire.Reply4Granted {
			io.Copy(c, c)
		}
		return
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).AddrPort().Port()
	c.Write(must(wire.AppendReply4(nil, cd, wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), port)))))
	peer, err := ln.Accept()
	if err != nil {
		return
	}
	defer peer.Close()
	c.Write(must(wire.AppendReply4(nil, cd, wire.AddrFromAddrPort(peer.RemoteAddr().(*net.TCPAddr).AddrPort()))))
	go io.Copy(peer, c)
	io.Copy(c, peer)
}

// udpProxy serves UDP ASSOCIATE (relay on loopback) and CONNECT, no auth.
type udpProxy struct {
	network string                               // relay network: "udp4" (default) or "udp6"
	bnd     func(relay netip.AddrPort) wire.Addr // BND sent; nil: the relay's address
	nat     bool                                 // answer from another socket than the relay
	rep     wire.Reply
	got     chan wire.Addr      // receives DST, if not nil
	raw     chan []byte         // receives each datagram from the client, if not nil
	assoc   chan *association   // receives each association, if not nil
	resolve func(string) string // maps names in DST.ADDR; nil: "localhost" → 127.0.0.1
}

type association struct {
	control  net.Conn
	relay    *net.UDPConn // receives from the client
	out      *net.UDPConn // sends to the client (relay, or another socket)
	clientMu sync.Mutex
	client   netip.AddrPort
	first    chan struct{} // closed on the first datagram from the client
	ended    chan struct{} // closed when the client closed the control conn
}

func (a *association) send(t testing.TB, b []byte) {
	t.Helper()
	<-a.first
	if _, err := a.out.WriteToUDPAddrPort(b, a.clientAddr()); err != nil {
		t.Error(err)
	}
}

func (a *association) clientAddr() netip.AddrPort {
	a.clientMu.Lock()
	defer a.clientMu.Unlock()
	return a.client
}

func (p udpProxy) serve(c net.Conn) {
	proxy{handle: func(c net.Conn, cmd wire.Command, dst wire.Addr) {
		if p.got != nil {
			p.got <- dst
		}
		switch {
		case p.rep != 0:
			c.Write(reply(p.rep, "0.0.0.0:0"))
		case cmd == wire.CmdConnect:
			p.connect(c, dst)
		case cmd != wire.CmdUDPAssociate:
			c.Write(reply(wire.ReplyCommandNotSupported, "0.0.0.0:0"))
		default:
			p.associate(c)
		}
	}}.serve(c)
}

func (p udpProxy) associate(c net.Conn) {
	network, loop := cmp.Or(p.network, "udp4"), netip.MustParseAddrPort("127.0.0.1:0")
	if network == "udp6" {
		loop = netip.MustParseAddrPort("[::1]:0")
	}
	var socks []*net.UDPConn // relay, up, out
	defer func() {
		for _, s := range socks {
			s.Close()
		}
	}()
	for range 3 {
		s, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(loop))
		if err != nil {
			return
		}
		socks = append(socks, s)
	}
	a := &association{control: c, relay: socks[0], out: socks[0], first: make(chan struct{}), ended: make(chan struct{})}
	if p.nat {
		a.out = socks[2]
	}
	relayAP := a.relay.LocalAddr().(*net.UDPAddr).AddrPort()
	bnd := wire.AddrFromAddrPort(relayAP)
	if p.bnd != nil {
		bnd = p.bnd(relayAP)
	}
	c.Write(must(wire.AppendReply(nil, wire.ReplySucceeded, bnd)))
	if p.assoc != nil {
		p.assoc <- a
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { p.fromClient(a, socks[1]) })
	wg.Go(func() { p.toClient(a, socks[1]) })
	if _, err := io.Copy(io.Discard, c); err == nil {
		close(a.ended)
	}
	for _, s := range socks {
		s.Close()
	}
}

func (p udpProxy) fromClient(a *association, up *net.UDPConn) {
	buf := make([]byte, 64<<10)
	var once sync.Once
	for {
		n, from, err := a.relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		a.clientMu.Lock()
		a.client = from
		a.clientMu.Unlock()
		once.Do(func() { close(a.first) })
		if p.raw != nil {
			p.raw <- append([]byte(nil), buf[:n]...)
		}
		frag, dst, hn, err := wire.ParseUDPHeader(buf[:n])
		if err != nil || frag != 0 {
			continue
		}
		if to, err := p.lookup(dst); err == nil {
			up.WriteToUDPAddrPort(buf[hn:n], to)
		}
	}
}

func (p udpProxy) toClient(a *association, up *net.UDPConn) {
	buf, hbuf := make([]byte, 64<<10), make([]byte, 0, wire.MaxUDPHeaderLen)
	for {
		n, from, err := up.ReadFromUDPAddrPort(buf[wire.MaxUDPHeaderLen:])
		if err != nil {
			return
		}
		hdr, _ := wire.AppendUDPHeader(hbuf[:0], 0, wire.AddrFromAddrPort(from))
		d := buf[wire.MaxUDPHeaderLen-len(hdr) : wire.MaxUDPHeaderLen+n]
		copy(d, hdr)
		a.out.WriteToUDPAddrPort(d, a.clientAddr())
	}
}

func (p udpProxy) lookup(a wire.Addr) (netip.AddrPort, error) {
	if !a.IsName() {
		return netip.AddrPortFrom(a.IP(), a.Port()), nil
	}
	host := "127.0.0.1"
	if p.resolve != nil {
		host = p.resolve(a.Name())
	}
	ip, err := netip.ParseAddr(host)
	return netip.AddrPortFrom(ip, a.Port()), err
}

func (p udpProxy) connect(c net.Conn, dst wire.Addr) {
	to, err := p.lookup(dst)
	if err != nil {
		return
	}
	t, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(to))
	if err != nil {
		c.Write(reply(wire.ReplyConnectionRefused, "0.0.0.0:0"))
		return
	}
	defer t.Close()
	c.Write(reply(wire.ReplySucceeded, t.LocalAddr().String()))
	go func() { io.Copy(t, c); t.CloseWrite() }()
	io.Copy(c, t)
}

func listenProxy(t *testing.T) string { return listen(t, udpProxy{}.serve) }

// udpServe answers each datagram with handle's result, if not nil.
func udpServe(t testing.TB, network string, handle func(b []byte) []byte) netip.AddrPort {
	t.Helper()
	loop := map[string]string{"udp4": "127.0.0.1:0", "udp6": "[::1]:0"}[network]
	c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(loop)))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if resp := handle(buf[:n]); resp != nil {
				c.WriteToUDPAddrPort(resp, from)
			}
		}
	})
	t.Cleanup(func() { c.Close(); wg.Wait() })
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func echo(b []byte) []byte { return b }

// dnsAnswer answers A with ip, others with no records; tc sets TC, no answers.
func dnsAnswer(ip netip.Addr, tc bool) func([]byte) []byte {
	return func(q []byte) []byte {
		if len(q) < 12 {
			return nil
		}
		end := 12
		for end < len(q) && q[end] != 0 {
			end += 1 + int(q[end])
		}
		end += 5 // root label, QTYPE, QCLASS
		if end > len(q) {
			return nil
		}
		r := append([]byte(nil), q[:end]...)
		r[2] |= 0x80 // QR
		r[3] = 0x80  // RA, NOERROR
		clear(r[6:12])
		if tc {
			r[2] |= 0x02
			return r
		}
		if binary.BigEndian.Uint16(q[end-4:]) == 1 { // A
			binary.BigEndian.PutUint16(r[6:], 1)
			r = append(r, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			r = append(r, ip.AsSlice()...)
		}
		return r
	}
}

// dnsTCP serves DNS over TCP with answer.
func dnsTCP(t testing.TB, answer func([]byte) []byte) string {
	return listen(t, func(c net.Conn) {
		for {
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			r := answer(q)
			c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
		}
	})
}

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

// memConn is the client end of an in-memory conn; the server side uses feed and closeServer.
type memConn struct {
	mu       sync.Mutex
	in       []byte // fed, not yet read
	consumed int    // bytes returned by Read
	chunk    int    // max bytes per Read; 0: as many as asked
	eof      bool   // server closed: EOF when in is drained
	rst      error  // returned by Read once in is drained (e.g. ECONNRESET)
	rdl, wdl time.Time
	closed   bool
	wake     chan struct{}
	writes   [][]byte
	asks     []int // len(b) of each Read

	// onWrite, if set, runs without mu after the deadline checks and returns Write's result.
	onWrite func(b []byte) (int, error)
	// onRead, if set, runs without mu as each Read starts.
	onRead func()
	// ignoreDeadlines mimics a conn without deadline support (some mux streams).
	ignoreDeadlines bool
	// readIgnoresClose keeps a blocked Read blocked after Close until releaseRead.
	readIgnoresClose bool
	releaseRead      chan struct{}

	closes atomic.Int32
}

func newMem(server ...[]byte) *memConn {
	return &memConn{in: slices.Concat(server...), wake: make(chan struct{}), releaseRead: make(chan struct{})}
}

func (c *memConn) broadcastLocked() {
	close(c.wake)
	c.wake = make(chan struct{})
}

func (c *memConn) feed(b []byte) {
	c.mu.Lock()
	c.in = append(c.in, b...)
	c.broadcastLocked()
	c.mu.Unlock()
}

func (c *memConn) closeServer() {
	c.mu.Lock()
	c.eof = true
	c.broadcastLocked()
	c.mu.Unlock()
}

// failAfter makes writes fail with errTest once n bytes are written.
func (c *memConn) failAfter(n int) {
	c.onWrite = func(b []byte) (int, error) {
		if len(b) <= n {
			n -= len(b)
			return len(b), nil
		}
		w := n
		n = 0
		return w, errTest
	}
}

func (c *memConn) expiredLocked() bool {
	return !c.ignoreDeadlines && !c.rdl.IsZero() && !time.Now().Before(c.rdl)
}

func (c *memConn) Read(b []byte) (int, error) {
	if c.onRead != nil {
		c.onRead()
	}
	c.mu.Lock()
	c.asks = append(c.asks, len(b))
	for {
		switch {
		case c.closed && !c.readIgnoresClose:
			c.mu.Unlock()
			return 0, net.ErrClosed
		case c.expiredLocked(): // as in package net, an expired deadline wins over buffered data
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		case len(c.in) > 0:
			n := len(b)
			if c.chunk > 0 {
				n = min(n, c.chunk)
			}
			n = copy(b[:n], c.in)
			c.in = c.in[n:]
			c.consumed += n
			c.mu.Unlock()
			return n, nil
		case c.rst != nil:
			c.mu.Unlock()
			return 0, c.rst
		case c.eof:
			c.mu.Unlock()
			return 0, io.EOF
		case c.closed:
			rel := c.releaseRead
			c.mu.Unlock()
			<-rel
			return 0, net.ErrClosed
		}
		wake, dl := c.wake, c.rdl
		c.mu.Unlock()
		var timer <-chan time.Time
		if !dl.IsZero() && !c.ignoreDeadlines {
			t := time.NewTimer(time.Until(dl))
			defer t.Stop()
			timer = t.C
		}
		select {
		case <-wake:
		case <-timer:
		}
		c.mu.Lock()
	}
}

func (c *memConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !c.ignoreDeadlines && !c.wdl.IsZero() && !time.Now().Before(c.wdl) {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	hook := c.onWrite
	c.mu.Unlock()
	n, err := len(b), error(nil)
	if hook != nil {
		n, err = hook(b)
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b[:n]...))
	c.mu.Unlock()
	return n, err
}

func (c *memConn) Close() error {
	c.closes.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	c.broadcastLocked()
	return nil
}

func (c *memConn) LocalAddr() net.Addr  { return memAddr("client") }
func (c *memConn) RemoteAddr() net.Addr { return memAddr("proxy") }

func (c *memConn) SetDeadline(t time.Time) error {
	if c.ignoreDeadlines {
		return errors.ErrUnsupported
	}
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.broadcastLocked()
	c.mu.Unlock()
	return nil
}

func (c *memConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.broadcastLocked()
	c.mu.Unlock()
	return nil
}

func (c *memConn) stats() (consumed int, writes [][]byte, asks []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consumed, slices.Clone(c.writes), slices.Clone(c.asks)
}

func (c *memConn) written() []byte {
	_, writes, _ := c.stats()
	return slices.Concat(writes...)
}

// chanConn shares no lock between Read and Close, so -race sees only
// socks0's synchronization.
type chanConn struct {
	net.Conn // nil: unused methods panic
	rd       chan []byte
}

func (c *chanConn) Read(b []byte) (int, error) {
	p, ok := <-c.rd
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(b, p), nil
}
func (c *chanConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *chanConn) Close() error                     { return nil }
func (c *chanConn) LocalAddr() net.Addr              { return memAddr("c") }
func (c *chanConn) RemoteAddr() net.Addr             { return memAddr("p") }
func (c *chanConn) SetDeadline(time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(time.Time) error { return nil }

// recConn records the calls on a TCP conn.
type recConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte // copies
	passed [][]byte // the slices passed to Write, to inspect the client's buffers
	reads  int      // bytes returned by Read
	dls    []time.Time
}

func (c *recConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, slices.Clone(b))
	c.passed = append(c.passed, b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.reads += n
	c.mu.Unlock()
	return n, err
}

func (c *recConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func (c *recConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.dls = append(c.dls, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *recConn) snapshot() (writes [][]byte, nread int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.writes), c.reads
}

// recDial is a ProxyDial sending each recConn it dials to ch.
func recDial(ch chan<- *recConn) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		rc := &recConn{Conn: c}
		ch <- rc
		return rc, nil
	}
}

// memDial is a ProxyDial returning c.
func memDial(c net.Conn) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) { return c, nil }
}

func noDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		t.Error("dialed the proxy")
		return nil, errTest
	}
}

// netDial dials addr directly, closing the conn when the test ends.
func netDial(t testing.TB, network, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// mustDial dials through d, closing the conn when the test ends.
func mustDial(t testing.TB, d *socks0.Dialer, network, target string) net.Conn {
	t.Helper()
	c, err := d.DialContext(t.Context(), network, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// mustListen is Listen through d, closing the listener when the test ends.
func mustListen(t testing.TB, d *socks0.Dialer, address string) net.Listener {
	t.Helper()
	ln, err := d.Listen(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// mustListenPacket is ListenPacket through d, closing the conn when the test ends.
func mustListenPacket(t testing.TB, d *socks0.Dialer, network, laddr string) *socks0.UDPConn {
	t.Helper()
	pc, err := d.ListenPacket(t.Context(), network, laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.(*socks0.UDPConn)
}

// client is a Conn over TCP to a proxy served by handle, recorded.
func client(t *testing.T, handle func(net.Conn), cfg *socks0.Config) (*socks0.Conn, *recConn) {
	t.Helper()
	rc := &recConn{Conn: netDial(t, "tcp", listen(t, handle))}
	c := socks0.Client(rc, "example.com:80", cfg)
	t.Cleanup(func() { c.Close() })
	return c, rc
}

func early(mod ...func(*socks0.Config)) *socks0.Config {
	cfg := &socks0.Config{Mode: socks0.ModeEarly}
	for _, f := range mod {
		f(cfg)
	}
	return cfg
}

func replyTimeout(d time.Duration) func(*socks0.Config) {
	return func(c *socks0.Config) { c.ReplyTimeout = d }
}

// hsRun runs a handshake for example.com:80 over mc, through a Dialer or
// Client; it returns the data conn: an L0/L1 Dialer's raw conn, else the *Conn.
func hsRun(t testing.TB, mc *memConn, mode socks0.Mode, auth socks0.Authenticator, viaDialer bool, trace *socks0.ClientTrace) (net.Conn, error) {
	t.Helper()
	cfg := &socks0.Config{Mode: mode, Auth: auth, Trace: trace}
	if !viaDialer {
		c := socks0.Client(mc, "example.com:80", cfg)
		return c, c.HandshakeContext(context.Background())
	}
	d := &socks0.Dialer{ProxyAddr: "proxy.example:1080", Config: cfg, ProxyDial: memDial(mc)}
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		return nil, err
	}
	if sc, ok := c.(*socks0.Conn); ok {
		return c, sc.HandshakeContext(context.Background())
	}
	return c, nil
}

// handshakeErr dials and, in ModeEarly, completes the handshake.
func handshakeErr(ctx context.Context, d *socks0.Dialer, target string) error {
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	if sc, ok := c.(*socks0.Conn); ok {
		return sc.HandshakeContext(ctx)
	}
	return nil
}

func handshakeErrOf(t *testing.T, err error) *socks0.HandshakeError {
	t.Helper()
	op, ok := err.(*net.OpError)
	if !ok || !strings.HasPrefix(op.Op, "socks ") {
		t.Fatalf("err = %#v; want *net.OpError{Op: socks …}", err)
	}
	he, ok := op.Err.(*socks0.HandshakeError)
	if !ok {
		t.Fatalf("OpError.Err = %#v; want *HandshakeError", op.Err)
	}
	return he
}

func isHandshakeErr(err error) bool {
	_, ok := errors.AsType[*socks0.HandshakeError](err)
	return ok
}

// readErr starts a one-byte Read and returns the channel of its error.
func readErr(r io.Reader) chan error {
	errc := make(chan error, 2)
	go func() { _, err := r.Read(make([]byte, 1)); errc <- err }()
	return errc
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

func roundTrip(t testing.TB, c net.Conn, msg string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func noPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()
	f()
}

// waitGoroutines waits up to 2 s for at most base goroutines.
func waitGoroutines(t testing.TB, base int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, want %d:\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func hasIPv6() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		ln.Close()
	}
	return err == nil
}

// events records trace hooks as "<tag>:<Hook> <detail>".
type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(format string, args ...any) {
	e.mu.Lock()
	e.log = append(e.log, fmt.Sprintf(format, args...))
	e.mu.Unlock()
}

func (e *events) get() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.log)
}

func errTag(err error) string {
	if err != nil {
		return "err"
	}
	return "ok"
}

func (e *events) trace(tag string) *socks0.ClientTrace {
	return &socks0.ClientTrace{
		ConnectStart:   func(network, addr string) { e.add("%s:ConnectStart", tag) },
		ConnectDone:    func(network, addr string, err error) { e.add("%s:ConnectDone %s", tag, errTag(err)) },
		WroteHandshake: func(err error) { e.add("%s:WroteHandshake %s", tag, errTag(err)) },
		GotMethod:      func(m wire.Method) { e.add("%s:GotMethod %v", tag, m) },
		AuthDone:       func(err error) { e.add("%s:AuthDone %s", tag, errTag(err)) },
		GotReply:       func(rep wire.Reply, bound wire.Addr) { e.add("%s:GotReply %v %v", tag, rep, bound) },
		HandshakeDone:  func(err error) { e.add("%s:HandshakeDone %s", tag, errTag(err)) },
		Accepted:       func(peer wire.Addr, err error) { e.add("%s:Accepted %v %s", tag, peer, errTag(err)) },
		RelayDialStart: func(network, _ string) { e.add("%s:RelayDialStart %s", tag, network) },
		RelayDialDone:  func(_, _ string, err error) { e.add("%s:RelayDialDone %s", tag, errTag(err)) },
	}
}

// only returns tag's events, untagged.
func only(log []string, tag string) []string {
	var out []string
	for _, l := range log {
		if s, ok := strings.CutPrefix(l, tag+":"); ok {
			out = append(out, s)
		}
	}
	return out
}

// interactive is an Authenticator that is not a Pipeliner.
type interactive struct{ m wire.Method }

func (a interactive) Method() wire.Method { return a.m }

func (a interactive) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	if _, err := rw.Write([]byte{1, 'x'}); err != nil {
		return err
	}
	var b [1]byte
	if _, err := io.ReadFull(rw, b[:]); err != nil {
		return err
	}
	if b[0] != 0 {
		return errors.Join(socks0.ErrAuthFailed, errTest)
	}
	return nil
}

// pipeliner: request "P", reply "ok!" padded to size bytes, or a rejection.
type pipeliner struct {
	reqErr error
	size   int
}

func (pipeliner) Method() wire.Method { return 0x80 }

func (pipeliner) Authenticate(context.Context, io.ReadWriter) error { return errTest }

func (p pipeliner) AppendRequest(dst []byte) ([]byte, error) {
	if p.reqErr != nil {
		return dst, p.reqErr
	}
	return append(dst, 'P'), nil
}

func (p pipeliner) ParseReply(b []byte) (int, error) {
	n := max(p.size, 3)
	switch {
	case len(b) < 3:
		return 3, wire.ErrIncomplete
	case string(b[:3]) != "ok!":
		return 0, errors.Join(socks0.ErrAuthFailed, errTest)
	case len(b) < n:
		return n, wire.ErrIncomplete
	}
	return n, nil
}

// resolver returns ips and err, recording "network host" of each lookup.
type resolver struct {
	ips []netip.Addr
	err error
	mu  sync.Mutex
	got []string
}

func (r *resolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.got = append(r.got, network+" "+host)
	r.mu.Unlock()
	return r.ips, r.err
}
