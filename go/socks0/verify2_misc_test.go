package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestV2UDPCtxAfterSetup(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	ctx, cancel := context.WithCancel(t.Context())
	c, err := d.DialContext(ctx, "udp", echoAP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	time.Sleep(20 * time.Millisecond)
	if s := roundTrip(t, c, "after cancel"); s != "after cancel" {
		t.Errorf("echo %q", s)
	}
	select {
	case <-c.(*socks0.UDPConn).Done():
		t.Error("association ended by ctx cancel")
	default:
	}
}

func TestV2CloseThenGC(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t)}
	base := runtime.NumGoroutine()
	for range 20 {
		c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	for range 5 {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	}
	waitGoroutines(t, base+2)
}

// Nothing is sent: config and unsupported, as for SOCKS4 with UDP.
func TestV2FastOpenUnsupportedKind(t *testing.T) {
	if socks0.FastOpenSupported {
		t.Skip("supported here")
	}
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1", ProxyDial: socks0.FastOpenDial(nil)}
	_, err := d.DialContext(t.Context(), "tcp", "example.com:80")
	he := handshakeErrOf(t, err)
	if k := socks0.KindOf(err); k != socks0.KindConfig || he.Stage != socks0.StageProxyDial {
		t.Errorf("TFO unsupported: KindOf = %q, stage %q: %v", k, he.Stage, err)
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("not ErrUnsupported: %v", err)
	}
}

func TestV2NewUDPConnNilErr(t *testing.T) {
	u := socks0.NewUDPConn(nil, nil, wire.Addr{})
	err := u.Err()
	if socks0.KindOf(err) != socks0.KindConfig || !socks0.IsProxyError(err) {
		t.Errorf("NewUDPConn(nil, nil).Err() = %v; KindOf %q", err, socks0.KindOf(err))
	}
	if _, err := u.WriteTo([]byte("x"), mustAddr("192.0.2.1:9")); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("WriteTo = %v", err)
	}
	if _, _, err := u.ReadFrom(make([]byte, 1)); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("ReadFrom = %v", err)
	}
	if err := u.SetDeadline(time.Now()); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("SetDeadline = %v", err)
	}
	select {
	case <-u.Done():
	default:
		t.Error("Done open")
	}
	// (nil, relay): the relay is closed, not leaked.
	rc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := socks0.NewUDPConn(nil, rc, wire.Addr{}).Err(); socks0.KindOf(err) != socks0.KindConfig {
		t.Errorf("NewUDPConn(nil, relay).Err() = %v", err)
	}
	if _, err := rc.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("relay left open: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if err := u.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("2nd Close = %v", err)
	}
}

// Review B1.
func TestV2SubstitutionResolveFails(t *testing.T) {
	unspec := func(ap netip.AddrPort) wire.Addr { return mustAddr(fmt.Sprintf("0.0.0.0:%d", ap.Port())) }
	assoc := make(chan *association, 1)
	real := listen(t, udpProxy{bnd: unspec, assoc: assoc}.serve)
	base := runtime.NumGoroutine()
	d := &socks0.Dialer{
		ProxyAddr: "no-such-host.invalid:1080",
		ProxyDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, real)
		},
	}
	_, err := d.ListenPacket(t.Context(), "udp", "")
	he := handshakeErrOf(t, err)
	if he.Stage != socks0.StageRelayDial || socks0.KindOf(err) != socks0.KindDNS {
		t.Errorf("err = %v; stage %q kind %q", err, he.Stage, socks0.KindOf(err))
	}
	select {
	case a := <-assoc:
		select {
		case <-a.ended:
		case <-time.After(time.Second):
			t.Error("control conn not closed")
		}
	case <-time.After(time.Second):
	}
	waitGoroutines(t, base+1)
}

// The relay's ECONNREFUSED may beat the control EOF.
func TestV2AssociationEndRefusedRace(t *testing.T) {
	assoc := make(chan *association, 1)
	d := &socks0.Dialer{ProxyAddr: listen(t, udpProxy{assoc: assoc}.serve)}
	counts := map[socks0.Kind]int{}
	for range 100 {
		c, err := d.DialContext(t.Context(), "udp", "192.0.2.1:9")
		if err != nil {
			t.Fatal(err)
		}
		a := <-assoc
		a.control.Close()
		var kind socks0.Kind
		for range 1000 {
			if _, err := c.Write([]byte("x")); err != nil {
				kind = socks0.KindOf(err)
				break
			}
			c.SetReadDeadline(time.Now().Add(time.Millisecond))
			if _, err := c.Read(make([]byte, 4)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				kind = socks0.KindOf(err)
				break
			}
		}
		counts[kind]++
		c.Close()
	}
	t.Logf("first error kind after the proxy ended the association: %v", counts)
	if counts[socks0.KindRefused] > 0 {
		t.Errorf("%d/100 associations ended by the proxy surfaced as KindRefused, not KindAssociation", counts[socks0.KindRefused])
	}
}

// A cleanup stuck on a Close-ignoring control Read must not block runtime.AddCleanup's goroutine.
func TestV2CleanupBlocksRuntime(t *testing.T) {
	mc := newMem()
	mc.readIgnoresClose = true
	mc.ignoreDeadlines = true
	defer close(mc.releaseRead)
	func() {
		rc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		if err != nil {
			t.Fatal(err)
		}
		_ = socks0.NewUDPConn(mc, rc, wire.Addr{}) // leaked
	}()
	for range 5 {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if mc.closes.Load() == 0 {
		t.Error("the leaked UDPConn's control conn was not closed by the GC cleanup")
	}
	ran := make(chan struct{})
	func() {
		x := new([16]byte)
		runtime.AddCleanup(x, func(ch chan struct{}) { close(ch) }, ran)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		select {
		case <-ran:
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Error("an unrelated cleanup did not run within 2s: the UDPConn cleanup blocks a runtime cleanup goroutine")
}

// The control conn's Read ignores Close and deadlines (any net.Conn may).
func TestCloseBoundedStuckControl(t *testing.T) {
	mc := newMem()
	mc.readIgnoresClose = true
	mc.ignoreDeadlines = true
	defer close(mc.releaseRead)
	rc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	u := socks0.NewUDPConn(mc, rc, wire.Addr{})
	start := time.Now()
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 900*time.Millisecond || el > 5*time.Second {
		t.Errorf("Close took %v, want about 1s", el)
	}
	if mc.closes.Load() == 0 {
		t.Error("control not closed")
	}
	if !errors.Is(u.Err(), net.ErrClosed) {
		t.Errorf("Err = %v", u.Err())
	}
}

func TestV2RelayListenDeadlinesAndOpError(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: listenProxy(t), RelayListen: new(net.ListenConfig).ListenPacket}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := pc.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) || socks0.KindOf(err) != socks0.KindTimeout {
		t.Errorf("ReadFrom = %v", err)
	}
	pc.SetWriteDeadline(time.Unix(1, 0))
	if _, err := pc.WriteTo([]byte("x"), mustAddr("192.0.2.1:9")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("WriteTo = %v", err)
	}
	pc.SetDeadline(time.Time{})
	if _, err := pc.WriteTo([]byte("x"), mustAddr("192.0.2.1:9")); err != nil {
		t.Errorf("WriteTo after clearing = %v", err)
	}

	rep7 := listen(t, udpProxy{rep: wire.ReplyCommandNotSupported}.serve)
	_, err = (&socks0.Dialer{ProxyAddr: rep7}).DialContext(t.Context(), "udp4", "192.0.2.1:53")
	oe, ok := err.(*net.OpError)
	if !ok || oe.Op != "socks udp associate" || oe.Net != "udp4" || oe.Source == nil || oe.Source.String() != rep7 ||
		oe.Addr == nil || oe.Addr.String() != "192.0.2.1:53" || !errors.Is(err, errors.ErrUnsupported) || socks0.KindOf(err) != socks0.KindReply {
		t.Errorf("err = %#v", err)
	}
	if he := handshakeErrOf(t, err); he.Stage != wire.StageReply {
		t.Errorf("stage %q", he.Stage)
	}
}
