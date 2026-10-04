package socks0_test

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

// memConn is the client end of an in-memory conn; the server uses feed and closeServer.
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
	// ignoreDeadlines mimics a conn without deadline support (some mux streams).
	ignoreDeadlines bool
	// readIgnoresClose keeps a blocked Read blocked after Close until releaseRead.
	readIgnoresClose bool
	releaseRead      chan struct{}

	closes atomic.Int32
}

func newMem(server ...[]byte) *memConn {
	c := &memConn{wake: make(chan struct{}), releaseRead: make(chan struct{})}
	for _, b := range server {
		c.in = append(c.in, b...)
	}
	return c
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

func (c *memConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	c.asks = append(c.asks, len(b))
	for {
		if c.closed && !c.readIgnoresClose {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		// As in package net, an expired deadline wins over buffered data.
		if !c.ignoreDeadlines && !c.rdl.IsZero() && !time.Now().Before(c.rdl) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.in) > 0 && len(b) > 0 {
			n := len(b)
			if c.chunk > 0 {
				n = min(n, c.chunk)
			}
			n = copy(b[:n], c.in)
			c.in = c.in[n:]
			c.consumed += n
			c.mu.Unlock()
			return n, nil
		}
		if len(b) == 0 && len(c.in) > 0 {
			c.mu.Unlock()
			return 0, nil
		}
		if c.rst != nil {
			c.mu.Unlock()
			return 0, c.rst
		}
		if c.eof {
			c.mu.Unlock()
			return 0, io.EOF
		}
		if c.closed && c.readIgnoresClose {
			rel := c.releaseRead
			c.mu.Unlock()
			<-rel
			return 0, net.ErrClosed
		}
		if !c.ignoreDeadlines && !c.rdl.IsZero() && !time.Now().Before(c.rdl) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
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

func (c *memConn) stats() (consumed, left int, writes [][]byte, asks []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consumed, len(c.in), append([][]byte(nil), c.writes...), append([]int(nil), c.asks...)
}

func (c *memConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var all []byte
	for _, w := range c.writes {
		all = append(all, w...)
	}
	return all
}

func checkGoroutines(t testing.TB, base int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines: %d, baseline %d\n%s", n, base, buf)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func numG() int { return runtime.NumGoroutine() }
