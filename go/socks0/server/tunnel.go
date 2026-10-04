package server

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

// Conn is the client conn after a successful Reply. Every read path (Read, WriteTo, NetConn) yields
// the bytes buffered during the handshake first, then any FIN seen meanwhile. It implements
// io.WriterTo, io.ReaderFrom, CloseWrite, CloseRead and syscall.Conn. Safe for one reader and one
// writer, plus Close and deadlines from any goroutine; after ServeSOCKS returned it is closed.
type Conn struct {
	sc     *serverConn
	closed bool // guarded by sc.mu
}

func (c *Conn) Read(b []byte) (int, error) {
	sc := c.sc
	if !sc.drained.Load() {
		if n, ok, err := sc.readBuffered(b); ok {
			sc.recv.Add(int64(n))
			return n, err
		}
	}
	n, err := sc.nc.Read(b)
	if !sc.handedOff.Load() {
		sc.recv.Add(int64(n))
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.sc.nc.Write(b)
	c.sc.sent.Add(int64(n))
	return n, err
}

// WriteTo writes the buffered bytes, then delegates to the conn's io.WriterTo (splice on Linux).
func (c *Conn) WriteTo(w io.Writer) (n int64, err error) {
	sc := c.sc
	if !sc.drained.Load() {
		n, err = sc.writeBufferedTo(w)
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
	var m int64
	if wt, ok := sc.nc.(io.WriterTo); ok {
		m, err = wt.WriteTo(w)
	} else {
		sc.ro.Reader = sc.nc
		m, err = io.Copy(w, &sc.ro)
	}
	if !sc.handedOff.Load() {
		sc.recv.Add(m)
	}
	return n + m, err
}

func (sc *serverConn) writeBufferedTo(w io.Writer) (int64, error) {
	b, ok, err := sc.takeBuffered()
	if !ok {
		return 0, err
	}
	m, werr := w.Write(b)
	sc.consumed(m)
	n := int64(m)
	sc.recv.Add(n)
	if werr != nil {
		return n, werr
	}
	_, _, err = sc.takeBuffered()
	return n, err
}

func (c *Conn) ReadFrom(r io.Reader) (n int64, err error) {
	if rf, ok := c.sc.nc.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		c.sc.wo.Writer = c.sc.nc
		n, err = io.Copy(&c.sc.wo, r)
	}
	c.sc.sent.Add(n)
	return n, err
}

// CloseWrite's error matches errors.ErrUnsupported if the conn cannot half-close.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.sc.nc.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errUnsupported
}

// CloseRead's error matches errors.ErrUnsupported if the conn cannot half-close.
func (c *Conn) CloseRead() error {
	if cr, ok := c.sc.nc.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return errUnsupported
}

// Close is idempotent, and nil after ServeSOCKS returned.
func (c *Conn) Close() error {
	sc := c.sc
	sc.mu.Lock()
	first := !c.closed && !sc.done
	c.closed = true
	sc.mu.Unlock()
	if !first {
		return nil
	}
	return sc.nc.Close()
}

func (c *Conn) Buffered() int {
	sc := c.sc
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.done || sc.handedOff.Load() || sc.bufp == nil {
		return 0
	}
	return sc.w - sc.r
}

// NetConn hands over the underlying conn and the unread buffered bytes, which the caller must consume
// first; buffered aliases the conn's buffer until ServeSOCKS returns. Later calls return none.
func (c *Conn) NetConn() (conn net.Conn, buffered []byte) {
	sc := c.sc
	sc.mu.Lock()
	defer sc.mu.Unlock()
	again := sc.handedOff.Load()
	sc.handedOff.Store(true)
	sc.drained.Store(true)
	if again || sc.done || sc.bufp == nil {
		return sc.nc, nil
	}
	buffered = sc.bufp.in[sc.r:sc.w:sc.w]
	sc.exposed = sc.exposed || len(buffered) > 0
	return sc.nc, buffered
}

// SyscallConn reads skip the buffered bytes; errors.ErrUnsupported means the conn has none.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	if s, ok := c.sc.nc.(syscall.Conn); ok {
		return s.SyscallConn()
	}
	return nil, errUnsupported
}

func (c *Conn) LocalAddr() net.Addr                { return c.sc.nc.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.sc.nc.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.sc.nc.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.sc.nc.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.sc.nc.SetWriteDeadline(t) }

func (sc *serverConn) readBuffered(b []byte) (n int, ok bool, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	switch {
	case sc.done:
		return 0, true, net.ErrClosed
	case sc.handedOff.Load():
		return 0, false, nil
	case sc.bufp != nil && sc.r < sc.w:
		n = copy(b, sc.bufp.in[sc.r:sc.w])
		if sc.r += n; sc.r == sc.w {
			sc.releaseLocked()
		}
		return n, true, nil
	case sc.readErr != nil:
		return 0, true, sc.readErr
	}
	sc.releaseLocked()
	sc.drained.Store(true)
	return 0, false, nil
}

// takeBuffered marks the bytes in use until consumed, for a write outside mu.
func (sc *serverConn) takeBuffered() (b []byte, ok bool, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	switch {
	case sc.done:
		return nil, false, net.ErrClosed
	case sc.handedOff.Load():
		return nil, false, nil
	case sc.bufp != nil && sc.r < sc.w:
		sc.reading = true
		return sc.bufp.in[sc.r:sc.w:sc.w], true, nil
	case sc.readErr != nil:
		return nil, false, sc.readErr
	}
	sc.releaseLocked()
	sc.drained.Store(true)
	return nil, false, nil
}

func (sc *serverConn) consumed(n int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.reading = false
	if sc.r += n; sc.r == sc.w || sc.done {
		sc.releaseLocked()
	}
}

// releaseLocked pools the buffer only if NetConn was never called (B2).
func (sc *serverConn) releaseLocked() {
	if sc.bufp != nil && !sc.reading && (!sc.handedOff.Load() || sc.done) {
		if !sc.exposed {
			putBuffers(sc.bufp)
		}
		sc.bufp = nil
	}
}

// readerOnly and writerOnly hide WriteTo and ReadFrom from io.Copy.
type readerOnly struct{ io.Reader }

type writerOnly struct{ io.Writer }
