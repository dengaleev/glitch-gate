package server

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

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
