package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func noPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()
	f()
}

func TestV2NilDialerNoPanic(t *testing.T) {
	var d *socks0.Dialer
	ctx := t.Context()
	for _, tc := range []struct {
		name string
		f    func() error
	}{
		{"DialContext udp", func() error { _, err := d.DialContext(ctx, "udp", "192.0.2.1:53"); return err }},
		{"DialContext udp4", func() error { _, err := d.DialContext(ctx, "udp4", "192.0.2.1:53"); return err }},
		{"ListenPacket", func() error { _, err := d.ListenPacket(ctx, "udp", ""); return err }},
		{"Listen", func() error { _, err := d.Listen(ctx, "tcp", "192.0.2.1:21"); return err }},
		{"LookupNetIP", func() error { _, err := d.LookupNetIP(ctx, "ip", "example.com"); return err }},
		{"LookupHost", func() error { _, err := d.LookupHost(ctx, "example.com"); return err }},
		{"LookupAddr", func() error { _, err := d.LookupAddr(ctx, "192.0.2.1"); return err }},
	} {
		noPanic(t, tc.name, func() {
			err := tc.f()
			if err == nil {
				t.Errorf("%s: no error", tc.name)
			} else if k := socks0.KindOf(err); k != socks0.KindConfig {
				t.Errorf("%s: KindOf = %q (%v), want config", tc.name, k, err)
			}
		})
	}
}

// A typed nil *wire.Addr must not make the error's Error panic.
func TestV2WriteToNilWireAddrPtr(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, err = pc.WriteTo([]byte("x"), (*wire.Addr)(nil))
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("WriteTo(nil *wire.Addr) = %v; want EINVAL", err)
	}
	noPanic(t, "unconnected err.Error()", func() { _ = err.Error() })

	c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.(*socks0.UDPConn).WriteTo([]byte("x"), (*wire.Addr)(nil))
	if !errors.Is(err, net.ErrWriteToConnected) {
		t.Errorf("connected WriteTo = %v", err)
	}
	noPanic(t, "connected err.Error()", func() { _ = err.Error() })
}

func TestV2LifetimeProxyEnds(t *testing.T) {
	for _, how := range []string{"close", "rst", "halfclose"} {
		t.Run(how, func(t *testing.T) {
			base := runtime.NumGoroutine()
			assoc := make(chan *association, 1)
			d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
			c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
			if err != nil {
				t.Fatal(err)
			}
			uc := c.(*socks0.UDPConn)
			a := <-assoc
			readErr := make(chan error, 1)
			go func() {
				_, err := c.Read(make([]byte, 100))
				readErr <- err
			}()
			time.Sleep(20 * time.Millisecond)
			switch how {
			case "close":
				a.control.Close()
			case "rst":
				a.control.(*net.TCPConn).SetLinger(0)
				a.control.Close()
			case "halfclose":
				a.control.(*net.TCPConn).CloseWrite()
			}
			select {
			case err := <-readErr:
				if !errors.Is(err, socks0.ErrAssociationClosed) || socks0.KindOf(err) != socks0.KindAssociation {
					t.Errorf("Read = %v (kind %q)", err, socks0.KindOf(err))
				}
				if errors.Is(err, net.ErrClosed) {
					t.Errorf("Read error matches net.ErrClosed: %v", err)
				}
				oe, ok := err.(*net.OpError)
				if !ok || oe.Op != "read" || oe.Net != "udp" {
					t.Errorf("Read error shape %#v", err)
				}
				switch how {
				case "close", "halfclose":
					if !errors.Is(err, io.EOF) {
						t.Errorf("EOF not wrapped: %v", err)
					}
				case "rst":
					if !errors.Is(err, eConnReset) {
						t.Logf("note: RST not ECONNRESET: %v", err)
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked Read not woken")
			}
			select {
			case <-uc.Done():
			case <-time.After(time.Second):
				t.Fatal("Done not closed")
			}
			if !errors.Is(uc.Err(), socks0.ErrAssociationClosed) {
				t.Errorf("Err = %v", uc.Err())
			}
			if _, err := c.Write([]byte("x")); !errors.Is(err, socks0.ErrAssociationClosed) {
				t.Errorf("Write = %v", err)
			}
			// Local Close wins over the proxy's end.
			if err := c.Close(); err != nil {
				t.Errorf("Close = %v", err)
			}
			if err := c.Close(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("2nd Close = %v", err)
			}
			if _, err := c.Read(make([]byte, 10)); !errors.Is(err, net.ErrClosed) {
				t.Errorf("Read after Close = %v", err)
			}
			if how == "halfclose" {
				a.control.Close()
			}
			waitGoroutines(t, base+2) // listener goroutines of the fake proxy may linger
		})
	}
}

func TestV2UserCloseNotAssociationClosed(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	for i := range 50 {
		c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
		if err != nil {
			t.Fatal(err)
		}
		uc := c.(*socks0.UDPConn)
		readErr := make(chan error, 1)
		go func() {
			_, err := c.Read(make([]byte, 10))
			readErr <- err
		}()
		if i%2 == 0 {
			time.Sleep(time.Millisecond)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		err = <-readErr
		if errors.Is(err, socks0.ErrAssociationClosed) || !errors.Is(err, net.ErrClosed) || socks0.KindOf(err) != socks0.KindClosed {
			t.Fatalf("Read after user Close = %v (kind %q)", err, socks0.KindOf(err))
		}
		if _, err := c.Write([]byte("x")); errors.Is(err, socks0.ErrAssociationClosed) || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after user Close = %v", err)
		}
		if err := uc.Err(); errors.Is(err, socks0.ErrAssociationClosed) || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Err after user Close = %v", err)
		}
		select {
		case <-uc.Done():
		default:
			t.Fatal("Done open after Close returned")
		}
	}
}

func TestV2CloseRacesProxyClose(t *testing.T) {
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	base := runtime.NumGoroutine()
	var refused atomic.Int32
	defer func() {
		if n := refused.Load(); n > 0 {
			t.Errorf("ECONNREFUSED instead of ErrAssociationClosed: %d times", n)
		}
	}()
	for range 100 {
		c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
		if err != nil {
			t.Fatal(err)
		}
		a := <-assoc
		var wg sync.WaitGroup
		check := func(what string, err error) {
			if err == nil {
				return
			}
			if errors.Is(err, eConnRefused) {
				refused.Add(1) // the proxy's relay closed before the watcher saw the control EOF
				return
			}
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, socks0.ErrAssociationClosed) {
				t.Errorf("%s: %v", what, err)
			}
		}
		wg.Go(func() { _, err := c.Read(make([]byte, 10)); check("read", err) })
		wg.Go(func() {
			for range 20 {
				_, err := c.Write([]byte("x"))
				check("write", err)
				if err != nil {
					return
				}
			}
		})
		wg.Go(func() { a.control.Close() })
		wg.Go(func() { c.Close() })
		wg.Go(func() { c.SetDeadline(time.Now().Add(time.Second)) })
		wg.Wait()
		<-c.(*socks0.UDPConn).Done()
	}
	waitGoroutines(t, base+2)
}

// Leaked UDPConns are closed by the GC.
func TestV2CleanupMany(t *testing.T) {
	const n = 10
	assoc := make(chan *association, n)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	runtime.GC()
	base := runtime.NumGoroutine()
	func() {
		for i := range n {
			var c net.Conn
			var err error
			if i%2 == 0 {
				c, err = d.DialContext(t.Context(), "udp", "192.0.2.1:9")
			} else {
				var pc net.PacketConn
				pc, err = d.ListenPacket(t.Context(), "udp", "")
				if pc != nil {
					c = pc.(net.Conn)
				}
			}
			if err != nil {
				t.Fatal(err)
			}

			c.SetReadDeadline(time.Now().Add(time.Millisecond))
			c.Read(make([]byte, 10))
		}
	}()
	var as []*association
	for range n {
		as = append(as, <-assoc)
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, a := range as {
		for {
			runtime.GC()
			select {
			case <-a.ended:
			case <-time.After(10 * time.Millisecond):
				if time.Now().After(deadline) {
					t.Fatal("leaked UDPConn not cleaned up")
				}
				continue
			}
			break
		}
	}
	waitGoroutines(t, base)
}

func TestV2Truncation(t *testing.T) {
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	target := mustAddr("192.0.2.7:7")
	c, err := d.DialContext(t.Context(), "udp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a := <-assoc
	c.Write([]byte("hello")) // let the proxy learn our address
	hdr, _ := wire.AppendUDPHeader(nil, 0, target)
	big := strings.Repeat("A", 3000)
	a.send(t, append(append([]byte(nil), hdr...), big...))
	a.send(t, append(append([]byte(nil), hdr...), "next"...))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 7)
	n, err := c.Read(buf)
	if err != nil || n != 7 || string(buf[:n]) != "AAAAAAA" {
		t.Fatalf("Read = %d %q %v", n, buf[:n], err)
	}
	buf = make([]byte, 100)
	n, err = c.Read(buf)
	if err != nil || string(buf[:n]) != "next" {
		t.Fatalf("2nd Read = %d %q %v", n, buf[:n], err)
	}
	// zero-length buffer
	a.send(t, append(append([]byte(nil), hdr...), "zzz"...))
	n, err = c.Read(nil)
	if err != nil || n != 0 {
		t.Fatalf("Read(nil) = %d %v", n, err)
	}
}

func TestV2DroppedFrom(t *testing.T) {
	assoc := make(chan *association, 1)
	type drop struct {
		from wire.Addr
		err  error
	}
	var mu sync.Mutex
	var drops []drop
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve), Config: &socks0.Config{Trace: &socks0.ClientTrace{
		DroppedDatagram: func(from wire.Addr, err error) {
			mu.Lock()
			drops = append(drops, drop{from, err})
			mu.Unlock()
		},
	}}}
	target := mustAddr("192.0.2.7:7")
	c, err := d.DialContext(t.Context(), "udp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a := <-assoc
	c.Write([]byte("hello"))
	other := mustAddr("192.0.2.8:7")
	frag, _ := wire.AppendUDPHeader(nil, 1, target)
	wrong, _ := wire.AppendUDPHeader(nil, 0, other)
	good, _ := wire.AppendUDPHeader(nil, 0, target)
	a.send(t, append(frag, "frag"...))
	a.send(t, append(wrong, "wrong"...))
	a.send(t, []byte{0, 0, 0, 9, 1, 2, 3})       // bad ATYP
	a.send(t, []byte{0, 0, 0, 1, 1, 2})          // truncated
	a.send(t, []byte{0, 0, 0, 3, 0, 0, 0, 1, 2}) // empty name
	a.send(t, append(good, "good"...))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "good" {
		t.Fatalf("Read = %q %v", buf[:n], err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(drops) != 5 {
		t.Fatalf("drops = %v", drops)
	}
	if drops[0].from != target || drops[0].err != socks0.ErrFragment {
		t.Errorf("frag drop = %v", drops[0])
	}
	if drops[1].from != other || drops[1].err != socks0.ErrWrongSource {
		t.Errorf("wrong drop = %v", drops[1])
	}
	for i, dr := range drops[2:] {
		pe, ok := errors.AsType[*socks0.ProtocolError](dr.err)
		if dr.from.IsValid() || !ok || pe.Stage != wire.StageUDPHeader {
			t.Errorf("malformed drop %d = %v %#v", i, dr.from, dr.err)
		}
	}
	// Only bad datagrams: the deadline holds across drops.
	mu.Unlock()
	go func() {
		for range 20 {
			a.send(t, append(wrong, "w"...))
			time.Sleep(10 * time.Millisecond)
		}
	}()
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	_, err = c.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > time.Second {
		t.Errorf("Read with only wrong datagrams = %v after %v", err, time.Since(start))
	}
	time.Sleep(250 * time.Millisecond)
	mu.Lock()
}

func TestV2RelayListenFilter(t *testing.T) {
	assoc := make(chan *association, 1)
	var mu sync.Mutex
	var drops []wire.Addr
	d := &socks0.Dialer{
		ProxyAddr: listen(t, udpProxy{assoc: assoc, nat: true}.serve),
		RelayListen: func(ctx context.Context, network, laddr string) (net.PacketConn, error) {
			return net.ListenPacket(network, laddr)
		},
		Config: &socks0.Config{Trace: &socks0.ClientTrace{DroppedDatagram: func(from wire.Addr, err error) {
			mu.Lock()
			drops = append(drops, from)
			mu.Unlock()
		}}},
	}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	a := <-assoc
	pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:9")))
	<-a.first
	// from another port of 127.0.0.1 (nat socket): accepted
	hdr, _ := wire.AppendUDPHeader(nil, 0, mustAddr("192.0.2.1:9"))
	a.send(t, append(hdr, "nat"...))
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 100)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "nat" || from.String() != "192.0.2.1:9" {
		t.Fatalf("ReadFrom = %q %v %v", buf[:n], from, err)
	}
	if !hasIPv6() {
		return
	}
	// From another host: dropped. The client socket is udp4, so use 127.0.0.2 (Linux).
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skip("no 127.0.0.2")
	}
	defer s.Close()
	a.clientMu.Lock()
	to := a.client
	a.clientMu.Unlock()
	s.WriteToUDPAddrPort(append(hdr, "spoof"...), to)
	a.send(t, append(hdr, "ok"...))
	n, _, err = pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("ReadFrom = %q %v", buf[:n], err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := wire.AddrFromAddrPort(s.LocalAddr().(*net.UDPAddr).AddrPort())
	if len(drops) != 1 || drops[0] != want {
		t.Errorf("drops = %v, want [%v]", drops, want)
	}
}

func TestV2ConcurrentHammer(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	base := runtime.NumGoroutine()
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	uc := pc.(*socks0.UDPConn)
	var stop atomic.Bool
	var wg sync.WaitGroup
	bad := func(err error) bool {
		return err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) &&
			!errors.Is(err, socks0.ErrAssociationClosed)
	}
	var got atomic.Int64
	for i := range 8 {
		wg.Go(func() {
			buf := make([]byte, 64+i)
			for !stop.Load() {
				var err error
				if i%2 == 0 {
					_, _, err = uc.ReadFromAddr(buf)
				} else {
					_, _, err = uc.ReadFrom(buf)
				}
				if bad(err) {
					t.Errorf("read: %v", err)
				}
				if err == nil {
					got.Add(1)
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
			}
		})
		wg.Go(func() {
			to := wire.AddrFromAddrPort(echoAP)
			msg := []byte(fmt.Sprint("msg", i))
			for !stop.Load() {
				var err error
				if i%2 == 0 {
					_, err = uc.WriteToAddr(msg, to)
				} else {
					_, err = uc.WriteTo(msg, net.UDPAddrFromAddrPort(echoAP))
				}
				if bad(err) {
					t.Errorf("write: %v", err)
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	wg.Go(func() {
		for !stop.Load() {
			uc.SetDeadline(time.Now().Add(5 * time.Millisecond))
			uc.SetReadDeadline(time.Time{})
			uc.SetWriteDeadline(time.Time{})
			_ = uc.Err()
			_ = uc.LocalAddr()
			time.Sleep(time.Millisecond)
		}
	})
	time.Sleep(300 * time.Millisecond)
	var cwg sync.WaitGroup
	for range 4 {
		cwg.Go(func() { uc.Close() })
	}
	cwg.Wait()
	stop.Store(true)
	wg.Wait()
	if got.Load() == 0 {
		t.Error("no datagram echoed")
	}
	waitGoroutines(t, base+2)
}

func TestV2Deadlines(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetWriteDeadline(time.Unix(1, 0))
	if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout {
		t.Errorf("Write past deadline = %v (%q)", err, socks0.KindOf(err))
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Errorf("Write error not a net.Error timeout: %#v", err)
	}
	c.SetWriteDeadline(time.Time{})
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Read = %v", err)
	}
	c.SetReadDeadline(time.Time{})

	if _, err := c.Write([]byte("x")); err != nil {
		t.Errorf("Write after deadlines = %v", err)
	}
}

func TestV2WriteErrors(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uc := c.(*socks0.UDPConn)
	if _, err := uc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9}); !errors.Is(err, net.ErrWriteToConnected) {
		t.Errorf("WriteTo connected = %v", err)
	}
	if _, err := uc.WriteToAddr([]byte("x"), mustAddr("192.0.2.1:9")); !errors.Is(err, net.ErrWriteToConnected) {
		t.Errorf("WriteToAddr connected = %v", err)
	}
	pc4, err := d.ListenPacket(t.Context(), "udp4", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc4.Close()
	if _, err := pc4.(net.Conn).Write([]byte("x")); !errors.Is(err, eDestAddrReq) {
		t.Errorf("Write unconnected = %v", err)
	}
	if _, err := pc4.WriteTo([]byte("x"), &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1}); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("WriteTo TCPAddr = %v", err)
	}
	if _, err := pc4.WriteTo([]byte("x"), nil); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("WriteTo nil = %v", err)
	}
	if _, err := pc4.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}); err == nil {
		t.Errorf("udp4 WriteTo IPv6: no error")
	}
	// 16-byte IPv4 in a *net.UDPAddr is IPv4
	if _, err := pc4.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}); err != nil {
		t.Errorf("udp4 WriteTo 16-byte IPv4 = %v", err)
	}
	if n, err := pc4.WriteTo([]byte("xy"), mustAddr("example.com:53")); err != nil || n != 2 {
		t.Errorf("udp4 WriteTo name = %d %v", n, err)
	}
	a := mustAddr("192.0.2.1:9")
	if n, err := pc4.WriteTo([]byte("xy"), &a); err != nil || n != 2 {
		t.Errorf("WriteTo *wire.Addr = %d %v", n, err)
	}
}

func TestV2ListenPacketAddress(t *testing.T) {
	got := make(chan wire.Addr, 10)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{got: got}.serve)}
	for _, tc := range []struct {
		addr string
		want string // DST sent, or "" for an error before connecting
	}{
		{"", "0.0.0.0:0"},
		{":0", "0.0.0.0:0"},
		{"0.0.0.0:0", "0.0.0.0:0"},
		{"[::]:0", "0.0.0.0:0"},
		{"192.0.2.1:0", "192.0.2.1:0"},
		{"192.0.2.1:5", ""}, // port needs RelayDial
		{"[::ffff:192.0.2.1]:0", "192.0.2.1:0"},
		{":53", ""},
		{"bogus", ""},
	} {
		pc, err := d.ListenPacket(t.Context(), "udp", tc.addr)
		if tc.want == "" {
			if err == nil {
				pc.Close()
				t.Errorf("%q: no error", tc.addr)
			} else if socks0.KindOf(err) != socks0.KindConfig {
				t.Errorf("%q: kind %q: %v", tc.addr, socks0.KindOf(err), err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.addr, err)
			continue
		}
		if dst := <-got; dst.String() != tc.want {
			t.Errorf("%q: DST %v, want %s", tc.addr, dst, tc.want)
		}
		pc.Close()
	}
	if _, err := d.ListenPacket(t.Context(), "tcp", ""); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("tcp: %v", err)
	}
}

func TestV2NewUDPConnCloseCloses(t *testing.T) {
	cc, cs := net.Pipe()
	rc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	u := socks0.NewUDPConn(cc, rc, wire.Addr{})
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	cs.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := cs.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("control not closed: %v", err)
	}
	if _, err := rc.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("relay not closed: %v", err)
	}
	// A nil relay: Close still closes control.
	cc2, cs2 := net.Pipe()
	u2 := socks0.NewUDPConn(cc2, nil, wire.Addr{})
	u2.Close()
	cs2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := cs2.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("NewUDPConn(control, nil).Close left control open: %v", err)
	}
}
