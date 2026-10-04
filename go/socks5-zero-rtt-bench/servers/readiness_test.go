package servers

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// refServer is a minimal io.ReadFull SOCKS5 server. A leaky one relays from
// the raw conn instead of the bufio.Reader it parsed with, the classic bug
// that strands early data.
func refServer(leaky bool) Server {
	return Server{Name: "ref", Serve: func(ln net.Listener, user, pass string) error {
		return serveEach(ln, func(c net.Conn) {
			br := bufio.NewReader(c)
			t, err := refHandshake(br, c, user, pass)
			if err != nil {
				return
			}
			defer t.Close()
			var clientData io.Reader = br
			if leaky {
				clientData = c
			}
			go func() { _, _ = io.Copy(t, clientData); t.Close() }()
			_, _ = io.Copy(c, t)
		})
	}}
}

// fullReader reads fixed-size fields, keeping the first error.
type fullReader struct {
	r   io.Reader
	err error
}

func (f *fullReader) next(n int) []byte {
	b := make([]byte, n)
	if f.err == nil {
		_, f.err = io.ReadFull(f.r, b)
	}
	return b
}

func refHandshake(r io.Reader, w io.Writer, user, pass string) (net.Conn, error) {
	f := &fullReader{r: r}
	method := byte(0)
	if user != "" {
		method = 2
	}
	f.next(int(f.next(2)[1])) // skip METHODS: the client offers only ours
	if f.err != nil {
		return nil, f.err
	}
	_, _ = w.Write([]byte{5, method})
	if user != "" {
		u := string(f.next(int(f.next(2)[1])))
		p := string(f.next(int(f.next(1)[0])))
		if f.err != nil || u != user || p != pass {
			_, _ = w.Write([]byte{1, 1})
			return nil, errors.Join(f.err, errors.New("auth failed"))
		}
		_, _ = w.Write([]byte{1, 0})
	}
	var host string
	switch h := f.next(4); h[3] {
	case 1:
		host = net.IP(f.next(net.IPv4len)).String()
	case 4:
		host = net.IP(f.next(net.IPv6len)).String()
	default:
		host = string(f.next(int(f.next(1)[0])))
	}
	port := binary.BigEndian.Uint16(f.next(2))
	if f.err != nil {
		return nil, f.err
	}
	t, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	rep := byte(0)
	if err != nil {
		rep = 4
	}
	_, _ = w.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
	return t, err
}

func TestCheckCorrectServer(t *testing.T) {
	rep := Check(t.Context(), refServer(false))
	for i, c := range rep.Cells {
		if !c.OK {
			t.Errorf("%s: %s %s", Columns[i], c.Reason, c.Detail)
		}
	}
}

func TestCheckLeakyServer(t *testing.T) {
	rep := Check(t.Context(), refServer(true))
	if c := rep.Cells[0]; !c.OK {
		t.Errorf("L1: %s %s", c.Reason, c.Detail)
	}
	for i, c := range rep.Cells[1:] {
		if c.OK || !strings.Contains(c.Reason, "lost") {
			t.Errorf("%s: OK=%v reason %q, want lost", Columns[i+1], c.OK, c.Reason)
		}
	}
}

// TestLeakyServerEverySplit guards that every split keeps the data early.
func TestLeakyServerEverySplit(t *testing.T) {
	s := refServer(true)
	for _, k := range matrix() {
		if k.size == 0 || k.user != "" {
			continue
		}
		if err := checkCase(t.Context(), s, k); err == nil {
			t.Errorf("%v: leaky server passed", k)
		}
	}
}

// TestLibraries logs each adapter's readiness. Only a broken no-auth L1
// fails: it means the adapter is miswired.
func TestLibraries(t *testing.T) {
	for _, s := range All {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			rep := Check(t.Context(), s)
			var row strings.Builder
			for i, c := range rep.Cells {
				mark := "ok"
				if !c.OK {
					mark = "FAIL(" + c.Reason + ")"
				}
				fmt.Fprintf(&row, " %s=%s", Columns[i], mark)
			}
			t.Logf("%s:%s (%d failing cases)", s.Name, row.String(), len(rep.Failures))
			for _, f := range rep.Failures {
				if strings.HasPrefix(f, "L1 noauth") {
					t.Error(f)
				}
			}
		})
	}
}
