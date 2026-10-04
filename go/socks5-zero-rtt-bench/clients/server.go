package clients

import (
	"bufio"
	"errors"
	"io"
	"net"
	"slices"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/internal/s5"
)

// server is a minimal in-process SOCKS5 server: it accepts any CONNECT and
// echoes the tunnel instead of dialing the target. It parses everything from
// one bufio.Reader that it then echoes, so pipelined bytes are never lost.
type server struct {
	user, pass string // empty user: no auth
	// hold delays the CONNECT reply until tunnel data arrives, at most hold.
	hold    time.Duration
	onReply func(connStats) // called just before the CONNECT reply
}

type connStats struct {
	reads int  // data-bearing socket reads before the reply
	early bool // tunnel data arrived before the reply
}

// listen serves s on a loopback port until stop is called.
func (s *server) listen() (addr string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// RST on close skips TIME_WAIT, so dial loops don't exhaust ports.
			c.(*net.TCPConn).SetLinger(0)
			go func() {
				defer c.Close()
				_ = s.serve(c)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }, nil
}

func (s *server) serve(c net.Conn) error {
	cr := &readCounter{r: c}
	r := bufio.NewReader(cr)
	buf := make([]byte, 2+255)
	if err := s.negotiate(c, r, buf); err != nil {
		return err
	}
	if err := s.authenticate(c, r); err != nil {
		return err
	}
	if err := readConnect(r, buf); err != nil {
		return err
	}
	st := connStats{reads: cr.reads, early: r.Buffered() > 0}
	if !st.early && s.hold > 0 {
		st.early = dataWithin(c, r, s.hold)
	}
	if s.onReply != nil {
		s.onReply(st)
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil { // succeeded, 0.0.0.0:0
		return err
	}
	return echo(c, r, buf)
}

// negotiate reads VER NMETHODS METHODS and selects s's method.
func (s *server) negotiate(c net.Conn, r *bufio.Reader, buf []byte) error {
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 5 {
		return errors.New("not SOCKS5")
	}
	methods := buf[2 : 2+buf[1]]
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	method := s5.Method(s.user)
	if !slices.Contains(methods, method) {
		c.Write([]byte{5, 0xff})
		return errors.New("no acceptable method")
	}
	_, err := c.Write([]byte{5, method})
	return err
}

// authenticate reads RFC 1929 VER ULEN UNAME PLEN PASSWD, if s has a user.
func (s *server) authenticate(c net.Conn, r *bufio.Reader) error {
	if s.user == "" {
		return nil
	}
	if _, err := r.Discard(1); err != nil {
		return err
	}
	user, err := readString(r)
	if err != nil {
		return err
	}
	pass, err := readString(r)
	if err != nil {
		return err
	}
	if user != s.user || pass != s.pass {
		c.Write([]byte{1, 1})
		return errors.New("bad credentials")
	}
	_, err = c.Write([]byte{1, 0})
	return err
}

// readConnect consumes VER CMD RSV ATYP DST.ADDR DST.PORT, ignoring the target.
func readConnect(r *bufio.Reader, buf []byte) error {
	if _, err := io.ReadFull(r, buf[:5]); err != nil { // up to DST.ADDR[0]
		return err
	}
	addrLen, ok := s5.AddrLen(buf[3], buf[4])
	if !ok {
		return errors.New("bad address type")
	}
	_, err := r.Discard(addrLen - 1 + 2)
	return err
}

// dataWithin reports whether more data arrives on c within d.
func dataWithin(c net.Conn, r *bufio.Reader, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	_, err := r.Peek(1)
	return err == nil
}

// echo copies r back to c through buf; io.Copy's 32 KiB buffer would dwarf
// the clients' allocations.
func echo(c net.Conn, r *bufio.Reader, buf []byte) error {
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, err := c.Write(buf[:n]); err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
}

// readString reads a 1-byte length and that many bytes.
func readString(r *bufio.Reader) (string, error) {
	n, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	b := make([]byte, n)
	_, err = io.ReadFull(r, b)
	return string(b), err
}

type readCounter struct {
	r     io.Reader
	reads int // reads that returned data
}

func (c *readCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.reads++
	}
	return n, err
}
