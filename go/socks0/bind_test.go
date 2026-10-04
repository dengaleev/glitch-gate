package socks0_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// bindProxy serves BIND: one peer on loopback, two replies, then relays.
type bindProxy struct {
	bnd        func(ln netip.AddrPort) wire.Addr // BND of reply 1; nil: the listener's address
	rep1, rep2 wire.Reply
	eof        bool           // close instead of reply 2, once the peer connected
	peerFirst  int            // bytes the peer sends to read before reply 2, sent with it in one write
	got        chan wire.Addr // receives DST, if not nil
}

func (p bindProxy) serve(c net.Conn) {
	if _, err := wire.ReadGreeting(c); err != nil {
		return
	}
	c.Write(wire.AppendMethodSelection(nil, wire.MethodNoAuth))
	cmd, dst, err := wire.ReadRequest(c)
	if err != nil || cmd != wire.CmdBind {
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
	b, _ := wire.AppendReply(nil, p.rep1, bnd)
	c.Write(b)
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
	b, _ = wire.AppendReply(nil, p.rep2, wire.AddrFromAddrPort(peer.RemoteAddr().(*net.TCPAddr).AddrPort()))
	c.Write(append(b, first...))
	if p.rep2 != 0 {
		return
	}
	go func() { io.Copy(peer, c); peer.(*net.TCPConn).CloseWrite() }()
	io.Copy(c, peer)
}

func TestListen(t *testing.T) {
	for _, mode := range modes {
		for _, peerFirst := range []int{0, 5} {
			t.Run(fmt.Sprintf("%v/coalesced=%v", mode, peerFirst > 0), func(t *testing.T) {
				got := make(chan wire.Addr, 1)
				conns := make(chan *recConn, 1)
				var events []string
				var mu sync.Mutex
				ev := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
				d := &socks0.Dialer{
					ProxyAddr: listen(t, bindProxy{got: got, peerFirst: peerFirst}.serve),
					ProxyDial: recDial(conns),
					Config: &socks0.Config{Mode: mode, Trace: &socks0.ClientTrace{
						GotReply:      func(rep wire.Reply, bound wire.Addr) { ev("reply") },
						HandshakeDone: func(err error) { ev(fmt.Sprint("done ", err)) },
						Accepted:      func(peer wire.Addr, err error) { ev(fmt.Sprint("accepted ", err)) },
					}},
				}
				ln, err := d.Listen(t.Context(), "tcp", "192.0.2.5:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				if dst := <-got; dst != mustAddr("192.0.2.5:0") {
					t.Errorf("DST %v", dst)
				}
				sl := ln.(*socks0.Listener)
				addr, ok := ln.Addr().(*net.TCPAddr)
				if !ok || addr.String() != sl.BoundAddr().String() {
					t.Fatalf("Addr %v, BoundAddr %v", ln.Addr(), sl.BoundAddr())
				}
				peer, err := net.DialTCP("tcp", nil, addr)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				if peerFirst > 0 {
					peer.Write([]byte("early"))
				}
				c, err := ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				sc := c.(*socks0.Conn)
				if c.RemoteAddr().String() != peer.LocalAddr().String() || sc.BoundAddr().String() != peer.LocalAddr().String() {
					t.Errorf("RemoteAddr %v, BoundAddr %v; peer %v", c.RemoteAddr(), sc.BoundAddr(), peer.LocalAddr())
				}
				if c.LocalAddr() != ln.Addr() {
					t.Errorf("LocalAddr %v", c.LocalAddr())
				}
				if peerFirst > 0 {
					buf := make([]byte, 5)
					if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "early" {
						t.Fatalf("peer's first bytes %q, %v", buf, err)
					}
				}
				c.Write([]byte("to peer"))
				buf := make([]byte, 7)
				if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "to peer" {
					t.Fatalf("peer read %q, %v", buf, err)
				}
				peer.Write([]byte("from peer"))
				buf = make([]byte, 9)
				if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "from peer" {
					t.Fatalf("read %q, %v", buf, err)
				}
				if err := sc.CloseWrite(); err != nil {
					t.Error(err)
				}
				if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Errorf("second Accept: %v", err)
				}
				if err := ln.Close(); err != nil {
					t.Errorf("Close after Accept: %v", err)
				}
				if _, err := io.ReadAll(peer); err != nil {
					t.Errorf("accepted conn did not survive Close: %v", err)
				}
				mu.Lock()
				defer mu.Unlock()
				if want := []string{"reply", "done <nil>", "accepted <nil>"}; !slices.Equal(events, want) {
					t.Errorf("trace %q, want %q", events, want)
				}
				writes, _, _ := (<-conns).snapshot()
				if mode != socks0.ModeSequential && len(writes) != 2 { // the handshake, then "to peer"
					t.Errorf("%d writes", len(writes))
				}
			})
		}
	}
}

func TestListenAddr(t *testing.T) {
	unspec := func(ap netip.AddrPort) wire.Addr {
		return wire.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port()))
	}
	named := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("proxy.example:%d", ap.Port())) }
	for _, tt := range []struct {
		name    string
		bnd     func(netip.AddrPort) wire.Addr
		address string
		dst     string
		host    string // ProxyAddr host
		want    string // Addr's type and host
	}{
		{name: "unspecified", bnd: unspec, address: "", dst: "0.0.0.0:0", want: "*net.TCPAddr 127.0.0.1"},
		{name: "unspecified named proxy", bnd: unspec, host: "localhost", dst: "198.51.100.1:21", address: "198.51.100.1:21", want: "*net.TCPAddr 127.0.0.1"},
		{name: "name", bnd: named, address: "0.0.0.0:0", dst: "0.0.0.0:0", want: "wire.Addr proxy.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan wire.Addr, 1)
			addr := listen(t, bindProxy{bnd: tt.bnd, got: got}.serve)
			_, port, _ := net.SplitHostPort(addr)
			d := &socks0.Dialer{ProxyAddr: net.JoinHostPort(cmp.Or(tt.host, "127.0.0.1"), port)}
			ln, err := d.Listen(t.Context(), "tcp", tt.address)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if dst := <-got; dst != mustAddr(tt.dst) {
				t.Errorf("DST %v", dst)
			}
			host, p, _ := net.SplitHostPort(ln.Addr().String())
			if s := fmt.Sprintf("%T %s", ln.Addr(), host); s != tt.want || p != fmt.Sprint(ln.(*socks0.Listener).BoundAddr().Port()) {
				t.Errorf("Addr %s (%s); want %s", s, ln.Addr(), tt.want)
			}
		})
	}
}

func TestListenErrors(t *testing.T) {
	zero := func(netip.AddrPort) wire.Addr { return mustAddr("127.0.0.1:0") }
	for _, tt := range []struct {
		name  string
		p     bindProxy
		stage string
		kind  socks0.Kind
		is    error
	}{
		{name: "reply 1", p: bindProxy{rep1: wire.ReplyNotAllowed}, stage: wire.StageReply, kind: socks0.KindReply},
		{name: "not supported", p: bindProxy{rep1: wire.ReplyCommandNotSupported}, stage: wire.StageReply, kind: socks0.KindReply, is: errors.ErrUnsupported},
		{name: "port 0", p: bindProxy{bnd: zero}, stage: wire.StageReply, kind: socks0.KindProtocol},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: listen(t, tt.p.serve)}
			ln, err := d.Listen(t.Context(), "tcp", "")
			if ln != nil {
				t.Fatalf("ln = %v", ln)
			}
			he := handshakeErrOf(t, err)
			if err.(*net.OpError).Op != "socks bind" || he.Stage != tt.stage || socks0.KindOf(err) != tt.kind || tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v; stage %q, kind %q", err, he.Stage, socks0.KindOf(err))
			}
		})
	}
	for _, tt := range []struct{ network, address string }{{"udp", ""}, {"tcp6", "192.0.2.1:0"}, {"tcp", "nope"}} {
		_, err := (&socks0.Dialer{ProxyAddr: "127.0.0.1:1"}).Listen(t.Context(), tt.network, tt.address)
		if socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("Listen(%q, %q) = %v", tt.network, tt.address, err)
		}
	}
}

func TestAcceptErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		p    bindProxy
		kind socks0.Kind
		is   error
	}{
		{name: "reply 2", p: bindProxy{rep2: wire.ReplyConnectionRefused}, kind: socks0.KindReply, is: eConnRefused},
		{name: "EOF", p: bindProxy{eof: true}, kind: socks0.KindEOF, is: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var accepted []error
			d := &socks0.Dialer{ProxyAddr: listen(t, tt.p.serve), Config: &socks0.Config{Trace: &socks0.ClientTrace{
				Accepted: func(_ wire.Addr, err error) { accepted = append(accepted, err) },
			}}}
			ln, err := d.Listen(t.Context(), "tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			peer, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			c, err := ln.Accept()
			if c != nil {
				t.Fatal("conn")
			}
			he := handshakeErrOf(t, err)
			if err.(*net.OpError).Op != "socks bind" || he.Stage != socks0.StageAccept || socks0.KindOf(err) != tt.kind || tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v; stage %q, kind %q", err, he.Stage, socks0.KindOf(err))
			}
			if pe, ok := errors.AsType[*socks0.ProtocolError](err); ok && pe.Stage != wire.StageReply {
				t.Errorf("ProtocolError stage %q", pe.Stage)
			}
			if len(accepted) != 1 || accepted[0] != err {
				t.Errorf("Accepted hook got %v", accepted)
			}
			if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("second Accept: %v", err)
			}
		})
	}
}

func TestListenerClose(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listen(t, bindProxy{}.serve)}
	ln, err := d.Listen(t.Context(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Go(func() {
			_, err := ln.Accept()
			errs <- err
		})
	}
	time.Sleep(20 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
			t.Errorf("Accept: %v", err)
		}
	}
	if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("second Close: %v", err)
	}
	if err := ln.(*socks0.Listener).SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetDeadline after Close: %v", err)
	}
}

func TestListenerDeadline(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listen(t, bindProxy{}.serve)}
	ln, err := d.Listen(t.Context(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sl := ln.(*socks0.Listener)
	if err := sl.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = ln.Accept()
	if !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || handshakeErrOf(t, err).Stage != socks0.StageAccept {
		t.Errorf("Accept = %v", err)
	}
	if !err.(*net.OpError).Timeout() {
		t.Error("Timeout() = false")
	}
}

func TestRequestBind(t *testing.T) {
	addr := listen(t, bindProxy{peerFirst: 3}.serve)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	bound, err := socks0.Request(t.Context(), conn, wire.CmdBind, mustAddr("0.0.0.0:0"), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.Dial("tcp", bound.String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.Write([]byte("abc"))
	rep, who, err := wire.ReadReply(conn, wire.CmdBind)
	if err != nil || rep != 0 || who.String() != peer.LocalAddr().String() {
		t.Fatalf("reply 2: %v, %v, %v", rep, who, err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "abc" {
		t.Fatalf("read %q, %v", buf, err)
	}
	if _, err := socks0.Request(t.Context(), nil, wire.CmdConnect, mustAddr("0.0.0.0:0"), nil); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("nil conn: %v", err)
	}
}

// Listener methods may run concurrently with an Accept that succeeds, also when errors name the
// proxy by the conn's address, ProxyAddr not parsing.
func TestListenerConcurrentAccept(t *testing.T) {
	addr := listen(t, bindProxy{}.serve)
	d := &socks0.Dialer{ProxyAddr: "proxy", ProxyDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, addr)
	}}
	ln, err := d.Listen(t.Context(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sl := ln.(*socks0.Listener)
	accepted := make(chan net.Conn, 1)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	accept := func() error { // all but one fail: another Accept is running or done
		c, err := sl.Accept()
		if c != nil {
			accepted <- c
		}
		return err
	}
	for _, f := range []func() error{func() error { return sl.SetDeadline(time.Time{}) }, accept, accept} {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := f(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("concurrent call: %v", err)
				}
			}
		})
	}
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var c net.Conn
	select {
	case c = <-accepted:
	case <-time.After(5 * time.Second):
		t.Error("no Accept returned a conn")
	}
	close(stop)
	wg.Wait()
	if c != nil {
		c.Close()
	}
	if err := sl.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetDeadline after Accept = %v", err)
	}
}
