//go:build linux

package socks0_test

// Needs a privileged container with server+client TFO and netem on lo:
//
//	sysctl -w net.ipv4.tcp_fastopen=3
//	tc qdisc add dev lo root netem delay 50ms   # RTT 100 ms
//	SOCKS0_NETEM_RTT=100ms go test -run TestFastOpenRoundTrips -v
//	SOCKS0_NETEM_TC=1 go test -run TestFastOpenDeferredErrors -v
//
// With a warm cookie (DESIGN.md §2): L2 dial + first Write + echo = 1 RTT,
// L1 dial = 1 RTT, L0 dial = 2 RTT; one RTT more each without TFO.

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestFastOpenRoundTrips(t *testing.T) {
	rttS := os.Getenv("SOCKS0_NETEM_RTT")
	if rttS == "" {
		t.Skip("SOCKS0_NETEM_RTT not set")
	}
	rtt, err := time.ParseDuration(rttS)
	if err != nil {
		t.Fatal(err)
	}
	if tfoSysctl(t)&3 != 3 {
		t.Skip("needs net.ipv4.tcp_fastopen=3")
	}
	addr := tfoListen(t, proxy{}.serve)
	measure := func(mode socks0.Mode, tfo bool) (time.Duration, bool) {
		d := &socks0.Dialer{ProxyAddr: addr, Config: &socks0.Config{Mode: mode}}
		if tfo {
			d.ProxyDial = socks0.FastOpenDial(nil)
		}
		start := time.Now()
		c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		dial := time.Since(start)
		if mode != socks0.ModeEarly {
			return dial, synData(t, c)
		}
		c.SetDeadline(time.Now().Add(5 * rtt))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo %q %v", buf, err)
		}
		return time.Since(start), synData(t, c)
	}
	for range 2 {
		measure(socks0.ModePipelined, true)
	}
	for _, tc := range []struct {
		mode socks0.Mode
		tfo  bool
		rtts int
	}{
		{socks0.ModeEarly, true, 1},
		{socks0.ModeEarly, false, 2},
		{socks0.ModePipelined, true, 1},
		{socks0.ModePipelined, false, 2},
		{socks0.ModeSequential, true, 2},
		{socks0.ModeSequential, false, 3},
	} {
		var best time.Duration
		var syn bool
		for i := range 3 {
			if d, s := measure(tc.mode, tc.tfo); i == 0 || d < best {
				best, syn = d, s
			}
		}
		got := float64(best) / float64(rtt)
		t.Logf("%v tfo=%v: %v = %.2f RTT (SYN data %v), want %d", tc.mode, tc.tfo, best, got, syn, tc.rtts)
		if got < float64(tc.rtts)-0.25 || got > float64(tc.rtts)+0.5 {
			t.Errorf("%v tfo=%v: %.2f RTT, want %d", tc.mode, tc.tfo, got, tc.rtts)
		}
		if tc.tfo && !syn {
			t.Errorf("%v tfo: no data in the SYN", tc.mode)
		}
	}
}

// Warm cookie: a blackholed SYN or refusal surfaces in the handshake.
func TestFastOpenDeferredErrors(t *testing.T) {
	if os.Getenv("SOCKS0_NETEM_TC") == "" {
		t.Skip("SOCKS0_NETEM_TC not set")
	}
	if tfoSysctl(t)&3 != 3 {
		t.Skip("needs net.ipv4.tcp_fastopen=3")
	}
	tc := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("tc", args...).CombinedOutput(); err != nil {
			t.Fatalf("tc %v: %v %s", args, err, out)
		}
	}
	addr := tfoListen(t, proxy{}.serve)
	for _, mode := range modes {
		d := &socks0.Dialer{ProxyAddr: addr, ProxyDial: socks0.FastOpenDial(nil), Config: &socks0.Config{Mode: mode}}
		for range 2 { // warm
			c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
	}
	t.Run("blackhole", func(t *testing.T) {
		tc("qdisc", "change", "dev", "lo", "root", "netem", "loss", "100%")
		defer tc("qdisc", "change", "dev", "lo", "root", "netem", "delay", "1ms")
		for _, mode := range modes[:2] {
			d := &socks0.Dialer{ProxyAddr: addr, ProxyDial: socks0.FastOpenDial(nil), Config: &socks0.Config{Mode: mode}}
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			start := time.Now()
			_, err := d.DialContext(ctx, "tcp", "example.com:80")
			cancel()
			el := time.Since(start)
			t.Logf("%v: %v after %v (kind %q)", mode, err, el, socks0.KindOf(err))
			if err == nil || socks0.KindOf(err) != socks0.KindTimeout || el > time.Second {
				t.Errorf("%v: %v after %v", mode, err, el)
				continue
			}
			if he, _ := errors.AsType[*socks0.HandshakeError](err); he.Stage != wire.StageGreeting && he.Stage != wire.StageMethodSelection {
				t.Errorf("%v: stage %q", mode, he.Stage)
			}
		}
		// ModeEarly: DialContext returns at once; the first Read fails within the deadline.
		d := &socks0.Dialer{ProxyAddr: addr, ProxyDial: socks0.FastOpenDial(nil), Config: &socks0.Config{Mode: socks0.ModeEarly}}
		c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("early dial: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(300 * time.Millisecond))
		c.Write([]byte("x"))
		if _, err = c.Read(make([]byte, 1)); socks0.KindOf(err) != socks0.KindTimeout {
			t.Errorf("early Read = %v", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closed := ln.Addr().String()
		ln.Close()
		for _, mode := range modes[:2] {
			d := &socks0.Dialer{ProxyAddr: closed, ProxyDial: socks0.FastOpenDial(nil), Config: &socks0.Config{Mode: mode}}
			_, err := d.DialContext(t.Context(), "tcp", "example.com:80")
			if !errors.Is(err, syscall.ECONNREFUSED) || socks0.KindOf(err) != socks0.KindRefused {
				t.Errorf("%v: %v (%q)", mode, err, socks0.KindOf(err))
			}
			if he, ok := errors.AsType[*socks0.HandshakeError](err); ok {
				t.Logf("%v: stage %q: %v", mode, he.Stage, err)
			}
		}
	})
}
