package clients

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

var auths = []struct{ name, user, pass string }{
	{"noauth", "", ""},
	{"userpass", "user", "secret"},
}

func listen(t *testing.T, s *server) string {
	t.Helper()
	addr, stop, err := s.listen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return addr
}

func TestOnce(t *testing.T) {
	for _, a := range auths {
		addr := listen(t, &server{user: a.user, pass: a.pass})
		for _, c := range All {
			t.Run(a.name+"/"+c.Name, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				if _, err := Once(ctx, c, addr, a.user, a.pass, anyTarget, []byte("hello")); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// TestOnceLarge: a first write far past the socket buffers must not
// deadlock the early-data client against its own echo.
func TestOnceLarge(t *testing.T) {
	addr := listen(t, &server{})
	for _, c := range All {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, err := Once(ctx, c, addr, "", "", anyTarget, make([]byte, 8<<20)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestOnceTimeout: Once honors ctx even if the library's Dial ignores it.
func TestOnceTimeout(t *testing.T) {
	addr := silentProxy(t)
	for _, c := range All {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := Once(ctx, c, addr, "", "", anyTarget, []byte("x"))
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("err = %v after %v, want a timeout after ~200ms", err, time.Since(start))
			}
		})
	}
}

// silentProxy accepts connections and never answers.
func silentProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	return ln.Addr().String()
}

func TestEarlyData(t *testing.T) {
	for _, a := range auths {
		for _, c := range All {
			t.Run(a.name+"/"+c.Name, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				early, err := EarlyData(ctx, c, a.user, a.pass)
				if err != nil {
					t.Fatal(err)
				}
				if want := c.Name == "ref L1+L2" || c.Name == "socks0 L1+L2"; early != want {
					t.Errorf("EarlyData = %v, want %v", early, want)
				}
			})
		}
	}
}

// TestReads counts server reads before the CONNECT reply: a lower bound on
// the client's round trips, an upper bound on its writes.
func TestReads(t *testing.T) {
	for _, a := range auths {
		for _, c := range All {
			t.Run(a.name+"/"+c.Name, func(t *testing.T) {
				reads := make(chan int, 1)
				addr := listen(t, &server{
					user: a.user, pass: a.pass,
					onReply: func(st connStats) { reads <- st.reads },
				})
				if _, err := Once(t.Context(), c, addr, a.user, a.pass, anyTarget, []byte("x")); err != nil {
					t.Fatal(err)
				}
				n := <-reads
				t.Logf("%d reads before the CONNECT reply", n)
				switch c.Name {
				case "ref L1", "ref L1+L2", "outline-sdk", "socks0 L1", "socks0 L1+L2":
					if n != 1 {
						t.Errorf("reads = %d, want 1", n)
					}
				case "x/net/proxy", "socks0 L0": // one RTT per message
					want := 2
					if a.user != "" {
						want = 3
					}
					if n < want {
						t.Errorf("reads = %d, want >= %d", n, want)
					}
				}
			})
		}
	}
}

func TestAllocs(t *testing.T) {
	if _, err := Allocs(All[0], "", ""); err != nil {
		t.Fatal(err)
	}
	broken := Client{"broken", func(context.Context, string, string, string, string) (net.Conn, error) {
		return nil, errors.New("boom")
	}}
	if _, err := Allocs(broken, "", ""); err == nil {
		t.Error("Allocs(broken): want an error")
	}
}

func TestBadPassword(t *testing.T) {
	addr := listen(t, &server{user: "user", pass: "secret"})
	for _, c := range All {
		t.Run(c.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := Once(ctx, c, addr, "user", "wrong", anyTarget, []byte("x"))
			if err == nil {
				t.Fatal("Once succeeded with a wrong password")
			}
			t.Log(err)
		})
	}
}
