package socks0_test

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// holdConn's first Write puts b on the wire, then holds until release: the handshake is sent
// but the call that sent it has not returned. reading closes on the first Read.
type holdConn struct {
	net.Conn
	wrote, release, reading chan struct{}
	wonce, ronce            sync.Once
}

func (c *holdConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.wonce.Do(func() { close(c.wrote); <-c.release })
	return n, err
}

func (c *holdConn) Read(b []byte) (int, error) {
	c.ronce.Do(func() { close(c.reading) })
	return c.Conn.Read(b)
}

// In ModeEarly, HandshakeDone runs last and after WroteHandshake even if the handshake ends while
// its first write is returning: by Close (no reader busy), by cancelling a reader of the replies,
// or by the replies a concurrent reader got.
func TestTraceEarlyDoneAfterWrote(t *testing.T) {
	cancelled := func(t *testing.T, c *socks0.Conn, hc *holdConn) {
		ctx, cancel := context.WithCancel(t.Context())
		errc := make(chan error, 1)
		go func() { errc <- c.HandshakeContext(ctx) }()
		<-hc.reading
		cancel()
		if err := <-errc; err == nil {
			t.Error("HandshakeContext = nil")
		}
	}
	for _, tc := range []struct {
		name  string
		serve func(net.Conn)
		end   func(*testing.T, *socks0.Conn, *holdConn) // ends the handshake while the write holds
		done  string
	}{
		{"close", scripted(nil, true), func(_ *testing.T, c *socks0.Conn, _ *holdConn) { c.Close() }, "HandshakeDone err"},
		{"cancel", scripted(nil, true), cancelled, "HandshakeDone err"},
		{"replies", proxy{}.serve, func(t *testing.T, c *socks0.Conn, _ *holdConn) {
			if err := c.HandshakeContext(t.Context()); err != nil {
				t.Error(err)
			}
		}, "HandshakeDone ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.Dial("tcp", listen(t, tc.serve))
			if err != nil {
				t.Fatal(err)
			}
			hc := &holdConn{Conn: raw, wrote: make(chan struct{}), release: make(chan struct{}), reading: make(chan struct{})}
			var ev events
			c := socks0.Client(hc, "example.com:80", early(func(cfg *socks0.Config) { cfg.Trace = ev.trace("t") }))
			defer c.Close()
			var wg sync.WaitGroup
			wg.Go(func() { c.Write([]byte("x")) })
			<-hc.wrote
			tc.end(t, c, hc)
			close(hc.release)
			wg.Wait()
			got := only(ev.get(), "t")
			wrote := slices.Index(got, "WroteHandshake ok")
			done := slices.IndexFunc(got, func(s string) bool { return s == "HandshakeDone ok" || s == "HandshakeDone err" })
			if wrote < 0 || done != len(got)-1 || got[done] != tc.done || wrote > done {
				t.Errorf("hooks %q; want WroteHandshake ok, then %s last", got, tc.done)
			}
		})
	}
}
