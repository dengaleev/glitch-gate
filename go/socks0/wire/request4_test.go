package wire_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type countReader struct {
	r     io.Reader
	reads int
}

func (c *countReader) Read(b []byte) (int, error) { c.reads++; return c.r.Read(b) }

// A server parsing its own buffer needs one read for a one-segment request.
func TestRequest4ReadCount(t *testing.T) {
	a, _ := wire.ParseAddr("example.com:80")
	b, err := wire.AppendRequest4(nil, wire.CmdConnect, a, "someuser")
	if err != nil {
		t.Fatal(err)
	}
	cr := &countReader{r: bytes.NewReader(append(slices.Clip(b), "early data"...))}
	_, got, user, err := wire.ReadRequest4(cr)
	if err != nil || got != a || string(user) != "someuser" {
		t.Fatalf("ReadRequest4 = %v %q %v", got, user, err)
	}
	if rest, _ := io.ReadAll(cr.r); string(rest) != "early data" {
		t.Errorf("ReadRequest4 over-read: left %q", rest)
	}
	t.Logf("ReadRequest4 of a %d-byte 4a request: %d reads", len(b), cr.reads)

	for have := range len(b) {
		_, _, _, n, err := wire.ParseRequest4(b[:have])
		if !errors.Is(err, wire.ErrIncomplete) || n <= have || n > len(b) {
			t.Fatalf("prefix %d: n %d, %v", have, n, err)
		}
	}

	buffered := func(r io.Reader) (reads int, addr wire.Addr, err error) {
		buf := make([]byte, 0, 512)
		for {
			_, addr, _, _, err = wire.ParseRequest4(buf)
			if !errors.Is(err, wire.ErrIncomplete) {
				return reads, addr, err
			}
			m, rerr := r.Read(buf[len(buf):cap(buf)])
			reads++
			buf = buf[:len(buf)+m]
			if rerr != nil {
				return reads, addr, rerr
			}
		}
	}
	cr = &countReader{r: bytes.NewReader(b)}
	if reads, got, err := buffered(cr); err != nil || got != a || reads != 1 {
		t.Errorf("buffered parse: %d reads, %v, %v", reads, got, err)
	}
}

func TestAppendRequest4Edges(t *testing.T) {
	for _, tc := range []struct {
		addr, user string
		ok         bool
	}{
		{"0.0.0.0:1", "", false},
		{"0.0.0.1:1", "", false},
		{"0.0.0.255:1", "", false},
		{"0.0.1.0:1", "", true},
		{"[::ffff:1.2.3.4]:1", "", true},
		{"[2001:db8::1]:1", "", false},
		{"a\x00b:1", "", false},
		{"ok.example:1", "u\x00", false},
		{"ok.example:1", strings.Repeat("u", 255), true},
		{"ok.example:1", strings.Repeat("u", 256), false},
	} {
		a, err := wire.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("%q: %v", tc.addr, err)
		}
		b, err := wire.AppendRequest4(nil, wire.CmdConnect, a, tc.user)
		if (err == nil) != tc.ok || err != nil && !errors.Is(err, wire.ErrInvalid) {
			t.Errorf("%q user %d bytes: %v", tc.addr, len(tc.user), err)
		}
		if err == nil {
			_, got, u, n, perr := wire.ParseRequest4(b)
			if perr != nil || got != a || string(u) != tc.user || n != len(b) {
				t.Errorf("round trip %q: %v %q %d %v", tc.addr, got, u, n, perr)
			}
		}
	}
	if a, _ := wire.ParseAddr("1.2.3.4:1"); a.IsName() {
		t.Fatal("1.2.3.4 is a name")
	}
}
