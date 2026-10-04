package server

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

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
