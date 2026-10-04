package clients

import (
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gateConn holds its first Write until gate closes and records each Write
// as it completes, i.e. in wire order. Read blocks until done closes.
type gateConn struct {
	net.Conn
	gate, entered, done chan struct{}
	started             atomic.Bool
	mu                  sync.Mutex
	writes              []string
}

func (c *gateConn) Write(p []byte) (int, error) {
	if c.started.CompareAndSwap(false, true) {
		close(c.entered)
		<-c.gate
	}
	c.mu.Lock()
	c.writes = append(c.writes, string(p))
	c.mu.Unlock()
	return len(p), nil
}

func (c *gateConn) Read([]byte) (int, error) {
	<-c.done
	return 0, io.EOF
}

// TestRefEarlyOrder: when Read sends the handshake first, a concurrent Write
// must not put its payload on the wire ahead of it.
func TestRefEarlyOrder(t *testing.T) {
	gc := &gateConn{gate: make(chan struct{}), entered: make(chan struct{}), done: make(chan struct{})}
	defer close(gc.done)
	c := &earlyConn{Conn: gc, hs: []byte("HS"), hsSent: make(chan struct{}), replied: make(chan struct{})}
	go c.Read(make([]byte, 1))
	<-gc.entered // Read is writing the handshake
	wrote := make(chan struct{})
	go func() { c.Write([]byte("data")); close(wrote) }()
	select {
	case <-wrote:
	case <-time.After(50 * time.Millisecond): // Write waits for the handshake
	}
	close(gc.gate)
	<-wrote
	gc.mu.Lock()
	defer gc.mu.Unlock()
	if want := []string{"HS", "data"}; !slices.Equal(gc.writes, want) {
		t.Fatalf("wire order %q, want %q", gc.writes, want)
	}
}
