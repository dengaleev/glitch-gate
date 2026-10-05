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
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestListen(t *testing.T) {
	for _, mode := range modes {
		for _, peerFirst := range []int{0, 5} {
			t.Run(fmt.Sprintf("%v/coalesced=%v", mode, peerFirst > 0), func(t *testing.T) {
				got := make(chan wire.Addr, 1)
				conns := make(chan *recConn, 1)
				var ev events
				d := &socks0.Dialer{ProxyAddr: listen(t, bindProxy{got: got, peerFirst: peerFirst}.serve), ProxyDial: recDial(conns), Config: &socks0.Config{Mode: mode, Trace: ev.trace("t")}}
				ln := mustListen(t, d, "192.0.2.5:0")
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
					if s := readN(t, c, 5); s != "early" {
						t.Fatalf("peer's first bytes %q", s)
					}
				}
				c.Write([]byte("to peer"))
				if s := readN(t, peer, 7); s != "to peer" {
					t.Fatalf("peer read %q", s)
				}
				peer.Write([]byte("from peer"))
				if s := readN(t, c, 9); s != "from peer" {
					t.Fatalf("read %q", s)
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
				want := []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod no auth", "GotReply succeeded " + sl.BoundAddr().String(),
					"HandshakeDone ok", "Accepted " + peer.LocalAddr().String() + " ok"}
				if got := only(ev.get(), "t"); !slices.Equal(got, want) {
					t.Errorf("trace %q, want %q", got, want)
				}
				if writes, _ := (<-conns).snapshot(); mode != socks0.ModeSequential && len(writes) != 2 { // the handshake, then "to peer"
					t.Errorf("%d writes", len(writes))
				}
			})
		}
	}
}

// Listen leaves reply 2 and the peer's data unread when they come with reply 1.
func TestListenRepliesCoalesced(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var ev events
			addr := listen(t, bind5(func(c net.Conn) {
				c.Write(slices.Concat(reply(0, "0.0.0.0:5555"), reply(0, "[2001:db8::7]:4444"), []byte("peer-data")))
				io.Copy(io.Discard, c)
			}))
			d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode, Trace: ev.trace("t")}}
			ln := mustListen(t, d, "")
			l := ln.(*socks0.Listener)
			if a, ok := l.Addr().(*net.TCPAddr); !ok || a.String() != "127.0.0.1:5555" || l.BoundAddr().String() != "0.0.0.0:5555" {
				t.Errorf("Addr = %#v, BoundAddr = %v", l.Addr(), l.BoundAddr())
			}
			time.Sleep(20 * time.Millisecond)
			c, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.RemoteAddr().String() != "[2001:db8::7]:4444" || c.LocalAddr().String() != "127.0.0.1:5555" || c.(*socks0.Conn).BoundAddr().String() != "[2001:db8::7]:4444" {
				t.Errorf("addrs %v %v", c.LocalAddr(), c.RemoteAddr())
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			if s := readN(t, c, len("peer-data")); s != "peer-data" {
				t.Errorf("Read = %q", s)
			}
			want := []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod no auth", "GotReply succeeded 0.0.0.0:5555", "HandshakeDone ok", "Accepted [2001:db8::7]:4444 ok"}
			if got := only(ev.get(), "t"); !slices.Equal(got, want) {
				t.Errorf("trace %q, want %q", got, want)
			}
		})
	}
}

func TestListenAddr(t *testing.T) {
	named := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("proxy.example:%d", ap.Port())) }
	for _, tt := range []struct {
		name    string
		bnd     func(netip.AddrPort) wire.Addr
		address string
		dst     string
		host    string // ProxyAddr host
		want    string // Addr's type and host
	}{
		{name: "unspecified", bnd: unspec4, address: "", dst: "0.0.0.0:0", want: "*net.TCPAddr 127.0.0.1"},
		{name: "unspecified named proxy", bnd: unspec4, host: "localhost", dst: "198.51.100.1:21", address: "198.51.100.1:21", want: "*net.TCPAddr 127.0.0.1"},
		{name: "name", bnd: named, address: "0.0.0.0:0", dst: "0.0.0.0:0", want: "wire.Addr proxy.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan wire.Addr, 1)
			_, port, _ := net.SplitHostPort(listen(t, bindProxy{bnd: tt.bnd, got: got}.serve))
			d := &socks0.Dialer{ProxyAddr: net.JoinHostPort(cmp.Or(tt.host, "127.0.0.1"), port)}
			ln := mustListen(t, d, tt.address)
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
			ln, err := (&socks0.Dialer{ProxyAddr: listen(t, tt.p.serve)}).Listen(t.Context(), "tcp", "")
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
		if _, err := (&socks0.Dialer{ProxyAddr: "127.0.0.1:1"}).Listen(t.Context(), tt.network, tt.address); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("Listen(%q, %q) = %v", tt.network, tt.address, err)
		}
	}
}

// A failed reply 2 fails the one Accept, then the Listener is done.
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
		for _, mode := range modes {
			t.Run(tt.name+"/"+mode.String(), func(t *testing.T) {
				var ev events
				d := &socks0.Dialer{ProxyAddr: listen(t, tt.p.serve), Config: &socks0.Config{Mode: mode, Trace: ev.trace("t")}}
				ln := mustListen(t, d, "")
				netDial(t, "tcp", ln.Addr().String())
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
				var replies, accepted []string
				for _, e := range only(ev.get(), "t") {
					if s, ok := strings.CutPrefix(e, "Accepted "); ok {
						accepted = append(accepted, s)
					} else if strings.HasPrefix(e, "GotReply ") {
						replies = append(replies, e)
					}
				}
				if len(replies) != 1 || len(accepted) != 1 || !strings.HasSuffix(accepted[0], " err") {
					t.Errorf("trace: replies %q, accepted %q", replies, accepted)
				}
				if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Errorf("second Accept: %v", err)
				}
				if err := ln.Close(); err != nil {
					t.Errorf("Close after a failed Accept = %v", err)
				}
			})
		}
	}
}

func TestListenerClose(t *testing.T) {
	var ev events
	d := &socks0.Dialer{ProxyAddr: listen(t, bindProxy{}.serve), Config: &socks0.Config{Trace: ev.trace("t")}}
	ln := mustListen(t, d, "")
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Go(func() { _, err := ln.Accept(); errs <- err })
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
	if n := len(slices.DeleteFunc(only(ev.get(), "t"), func(s string) bool { return !strings.HasPrefix(s, "Accepted") })); n != 1 {
		t.Errorf("Accepted ran %d times", n)
	}
}

func TestListenerDeadline(t *testing.T) {
	ln, err := (&socks0.Dialer{ProxyAddr: listen(t, bindProxy{}.serve)}).Listen(t.Context(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sl := ln.(*socks0.Listener)
	if err := sl.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = ln.Accept()
	if !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout || handshakeErrOf(t, err).Stage != socks0.StageAccept || time.Since(start) > time.Second {
		t.Errorf("Accept = %v", err)
	}
	if !err.(net.Error).Timeout() {
		t.Error("Timeout() = false")
	}
	if err := sl.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetDeadline after Accept = %v", err)
	}
}

// Listen's ctx bounds Listen, not Accept.
func TestListenContext(t *testing.T) {
	release := make(chan struct{})
	d := &socks0.Dialer{ProxyAddr: listen(t, bind5(func(c net.Conn) {
		c.Write(reply(0, "127.0.0.1:5555"))
		<-release
		c.Write(append(reply(0, "192.0.2.9:1"), "hi"...))
		io.Copy(io.Discard, c)
	}))}
	ctx, cancel := context.WithCancel(t.Context())
	ln, err := d.Listen(ctx, "tcp", "192.0.2.9:0")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	close(release)
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept after ctx cancel = %v", err)
	}
	c.Close()

	d = &socks0.Dialer{ProxyAddr: listen(t, bind5(func(c net.Conn) { io.Copy(io.Discard, c) }))}
	base := runtime.NumGoroutine()
	ctx, cancel = context.WithCancel(t.Context())
	time.AfterFunc(30*time.Millisecond, cancel)
	_, err = d.Listen(ctx, "tcp", "192.0.2.9:0")
	if !errors.Is(err, context.Canceled) || socks0.KindOf(err) != socks0.KindCanceled || handshakeErrOf(t, err).Stage != wire.StageReply {
		t.Fatalf("Listen = %v (%q)", err, socks0.KindOf(err))
	}
	waitGoroutines(t, base+1)
}

func TestRequestBind(t *testing.T) {
	conn := netDial(t, "tcp", listen(t, bindProxy{peerFirst: 3}.serve))
	bound, err := socks0.Request(t.Context(), conn, wire.CmdBind, mustAddr("0.0.0.0:0"), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := netDial(t, "tcp", bound.String())
	peer.Write([]byte("abc"))
	rep, who, err := wire.ReadReply(conn, wire.CmdBind)
	if err != nil || rep != 0 || who.String() != peer.LocalAddr().String() {
		t.Fatalf("reply 2: %v, %v, %v", rep, who, err)
	}
	if s := readN(t, conn, 3); s != "abc" {
		t.Fatalf("read %q", s)
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
	ln := mustListen(t, d, "")
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
	netDial(t, "tcp", ln.Addr().String())
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
