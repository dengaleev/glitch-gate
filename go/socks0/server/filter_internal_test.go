package server

// Filter internals: the vetted dial without Control, and the own-host check.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func mustAddr(s string) wire.Addr {
	a, err := wire.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

type resolverFunc func() ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) { return f() }

// dialVetted, ConnectHandler's dial where net.Dialer runs no Control (plan9), vets every address
// with Filter and the own-host check before any packet and dials exactly the vetted IPs.
func TestDialVetted(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
			accepted <- struct{}{}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).AddrPort().Port()
	target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	ip := netip.MustParseAddr
	denied, broke := &DeniedError{Reason: "test"}, errors.New("resolver broke")
	answer := func(ips ...string) resolverFunc {
		return func() ([]netip.Addr, error) {
			var out []netip.Addr
			for _, s := range ips {
				out = append(out, ip(s))
			}
			return out, nil
		}
	}
	allowExcept := func(deny ...string) Filter {
		return func(_ *Request, _ string, a netip.AddrPort) error {
			if slices.Contains(deny, a.Addr().String()) {
				return denied
			}
			return nil
		}
	}
	// notSelf denies an address only when the own-host check asks again with it as LocalAddr.
	notSelf := Filter(func(r *Request, _ string, a netip.AddrPort) error {
		if ipOf(r.LocalAddr) == a.Addr() {
			return denied
		}
		return nil
	})
	isDNS := func(err error) bool { _, ok := errors.AsType[*net.DNSError](err); return ok }
	isDial := func(err error) bool {
		op, ok := errors.AsType[*net.OpError](err)
		return ok && op.Op == "dial" && !errors.Is(err, ErrNotAllowed)
	}
	for _, tc := range []struct {
		name    string
		addr    string
		filter  Filter
		res     resolverFunc
		timeout time.Duration
		want    func(error) bool // nil: connected to target
	}{
		{"literal allowed", target.String(), AllowAll, nil, 0, nil},
		{"literal denied", target.String(), nil, nil, 0, isDenied},
		{"literal mapped", netip.AddrPortFrom(ip("::ffff:127.0.0.1"), port).String(), allowExcept("127.0.0.1"), nil, 0, isDenied},
		{"literal own host", target.String(), notSelf, nil, 0, isDenied},
		{"name: denied IP skipped", "x.test", allowExcept("192.0.2.1"), answer("192.0.2.1", "::ffff:127.0.0.1"), time.Minute, nil},
		{"name: failed dial, next IP", "x.test", AllowAll, answer("::1", "127.0.0.1"), 0, nil}, // the listener is IPv4 only
		{"name: all dials fail", "x.test", AllowAll, answer("::1"), 0, isDial},
		{"name: all denied", "x.test", nil, answer("127.0.0.1", "10.0.0.1"), 0, isDenied},
		{"name: own host", "x.test", notSelf, answer("127.0.0.1"), 0, isDenied},
		{"name: lookup error", "x.test", AllowAll, func() ([]netip.Addr, error) { return nil, broke }, 0, func(err error) bool { return errors.Is(err, broke) }},
		{"name: no answer", "x.test", AllowAll, answer(), 0, isDNS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.addr
			if tc.res != nil { // a name, at the listener's port
				addr = net.JoinHostPort(addr, strconv.Itoa(int(port)))
			}
			r := &Request{Command: wire.CmdConnect, Addr: mustAddr(addr), LocalAddr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 1080}}
			h := &ConnectHandler{Filter: tc.filter}
			c, err := h.dialVetted(t.Context(), r, &net.Dialer{Timeout: tc.timeout}, tc.res)
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if got := addrPortOf(c.RemoteAddr()); got != target {
					t.Errorf("connected to %v; want %v", got, target)
				}
				<-accepted
				return
			}
			if c != nil {
				c.Close()
			}
			if !tc.want(err) {
				t.Fatalf("err = %v", err)
			}
			select {
			case <-accepted:
				t.Error("connected to a denied address")
			case <-time.After(10 * time.Millisecond):
			}
		})
	}
}

func isDenied(err error) bool { return errors.Is(err, ErrNotAllowed) }

// setHost holds hostMu: a conn of another test may be checking.
func setHost(t *testing.T, list func() ([]net.Addr, error), ttl time.Duration) {
	t.Helper()
	hostMu.Lock()
	oldList, oldTTL := interfaceAddrs, hostTTL
	interfaceAddrs, hostTTL = list, ttl
	cachedHostAddrs.Store(nil)
	hostMu.Unlock()
	t.Cleanup(func() {
		hostMu.Lock()
		interfaceAddrs, hostTTL = oldList, oldTTL
		cachedHostAddrs.Store(nil)
		hostMu.Unlock()
	})
}

func TestOwnHost(t *testing.T) {
	calls := 0
	setHost(t, func() ([]net.Addr, error) {
		calls++
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)}, // 16-byte form
			&net.IPNet{IP: net.ParseIP("2001:db8::7"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("fe80::7")}, // plan9, windows style
			&net.UnixAddr{Name: "odd"},
		}, nil
	}, time.Hour)
	ap := netip.MustParseAddrPort
	for _, tc := range []struct {
		dst  string
		self bool
	}{
		{"192.0.2.7:80", true},
		{"[::ffff:192.0.2.7]:80", true},
		{"[2001:db8::7]:80", true},
		{"[fe80::7%eth0]:80", true},
		{"[64:ff9b::c000:207]:80", true}, // NAT64 of 192.0.2.7
		{"[2002:c000:207::1]:80", true},  // 6to4 of 192.0.2.7
		{"127.0.0.1:80", true},
		{"127.3.2.1:80", true},
		{"[::1]:80", true},
		{"0.0.0.0:80", true},
		{"[::]:80", true},
		{"192.0.2.8:80", false},
		{"[2001:db8::8]:80", false},
		{"8.8.8.8:53", false},
	} {
		dst := normalize(ap(tc.dst)) // as ownHost's callers pass it
		got := ownHost(dst)
		if tc.self && got != dst || !tc.self && got.IsValid() {
			t.Errorf("ownHost(%v) = %v, self %v", dst, got, tc.self)
		}
	}
	if calls != 1 {
		t.Errorf("listed %d times, want 1 (cached)", calls)
	}

	// Expired: a new address is seen.
	setHost(t, func() ([]net.Addr, error) {
		calls++
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.9").To4(), Mask: net.CIDRMask(32, 32)}}, nil
	}, time.Nanosecond)
	calls = 0
	for range 3 {
		time.Sleep(time.Millisecond)
		if !ownHost(ap("192.0.2.9:1")).IsValid() {
			t.Fatal("new address not seen")
		}
	}
	if calls != 3 {
		t.Errorf("listed %d times, want 3", calls)
	}
}

func TestOwnHostRouteFallback(t *testing.T) {
	setHost(t, func() ([]net.Addr, error) { return nil, errors.New("no listing") }, time.Hour)
	lo := netip.MustParseAddrPort("127.0.0.1:9")
	if got := ownHost(lo); got.Addr() != lo.Addr() {
		t.Errorf("ownHost(%v) = %v", lo, got)
	}
	other := netip.MustParseAddrPort("192.0.2.1:9")
	if got := ownHost(other); got.Addr() == other.Addr() { // the source address, if routed
		t.Errorf("another host: %v", got)
	}
}

// Concurrent Filter.checkOwnHost (Happy Eyeballs): one call claims the conn's
// scratch Request, the others allocate; each sees its own LocalAddr.
func TestFilterSelfConcurrent(t *testing.T) {
	sc := &serverConn{s: &Server{}}
	r := &sc.req
	r.sc, r.LocalAddr = sc, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 1080}
	var mu sync.Mutex
	seen := map[string]int{}
	f := Filter(func(r *Request, _ string, a netip.AddrPort) error {
		if got := addrPortOf(r.LocalAddr); got != a {
			return errors.New("LocalAddr " + got.String() + " for " + a.String())
		}
		mu.Lock()
		seen[a.String()]++
		mu.Unlock()
		time.Sleep(time.Millisecond)
		return nil
	})
	var wg sync.WaitGroup
	for i := range 16 {
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 80)
		if i%2 == 1 {
			dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)}), 80)
		}
		wg.Go(func() {
			if err := f.checkOwnHost(r, "tcp", dst, dst, nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if len(seen) != 16 {
		t.Errorf("filter saw %d targets, want 16", len(seen))
	}
	if sc.scratch.busy.Load() {
		t.Error("scratch still claimed")
	}
	// Filter.Control with a Request of one's own, or none.
	for _, r := range []*Request{{}, nil} {
		dst := netip.MustParseAddrPort("192.0.2.1:80")
		if err := f.checkOwnHost(r, "tcp", dst, dst, nil); err != nil {
			t.Error(err)
		}
	}
}

// While a refresh holds hostMu, an expired listing is returned at once; with none cached yet, the
// caller waits for the refresh.
func TestOwnHostStaleWhileRefreshing(t *testing.T) {
	calls := 0
	setHost(t, func() ([]net.Addr, error) {
		calls++
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.7").To4(), Mask: net.CIDRMask(32, 32)}}, nil
	}, time.Nanosecond)

	hostMu.Lock() // a refresh in progress, nothing cached
	got := make(chan *hostAddrs)
	go func() { got <- currentHostAddrs() }()
	select {
	case <-got:
		t.Fatal("returned without a listing")
	case <-time.After(10 * time.Millisecond):
	}
	hostMu.Unlock()
	h := <-got
	if _, ok := h.ips[netip.MustParseAddr("192.0.2.7")]; !ok || calls != 1 {
		t.Fatalf("listing %v after %d calls", h.ips, calls)
	}

	time.Sleep(time.Millisecond) // expired
	hostMu.Lock()
	stale := currentHostAddrs()
	hostMu.Unlock()
	if stale != h || calls != 1 {
		t.Errorf("a refresh in progress blocked or replaced the expired listing (%d calls)", calls)
	}
	if currentHostAddrs() == h || calls != 2 {
		t.Errorf("not refreshed (%d calls)", calls)
	}
}
