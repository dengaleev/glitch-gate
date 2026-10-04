package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/clients"
	"github.com/dengaleev/glitch-gate/go/socks5-zero-rtt-bench/servers"
)

var socks0Modes = []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly}

// earlyDataLosers are the servers whose readiness rows fail every L2 cell.
var earlyDataLosers = map[string]bool{"sagernet/sing": true, "go-gost/x (gost)": true}

// TestInteropSocks0 runs socks0 in every mode against every server: auth ×
// ATYP × payload, echoed by a target behind the proxy. L0 and L1 must pass
// everywhere; L2 must pass on the ready servers and lose the head of the
// data on the two that drop early bytes, exactly as the readiness table says.
func TestInteropSocks0(t *testing.T) {
	auths := []struct{ name, user, pass string }{{"noauth", "", ""}, {"userpass", "user", "pass"}}
	hosts := []struct{ name, host string }{{"ipv4", "127.0.0.1"}, {"domain", "localhost"}}
	sizes := []int{64, 1536, 64 << 10}
	payload := make([]byte, 64<<10) // non-repeating, so a lost head shows
	_, _ = rand.NewChaCha8([32]byte{'s', 'o', 'c', 'k', 's', '0'}).Read(payload)

	port := echoTarget(t)
	for _, s := range servers.All {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			for _, a := range auths {
				proxy := serveProxy(t, s, a.user, a.pass)
				for _, mode := range socks0Modes {
					for _, h := range hosts {
						for _, size := range sizes {
							name := fmt.Sprintf("%s/%s/%s/%d", a.name, mode, h.name, size)
							t.Run(name, func(t *testing.T) {
								t.Parallel()
								cfg := &socks0.Config{Mode: mode}
								if a.user != "" {
									cfg.Auth = socks0.UserPass{Username: a.user, Password: a.pass}
								}
								d := &socks0.Dialer{ProxyAddr: proxy, Config: cfg}
								err := echoOnce(t.Context(), d, net.JoinHostPort(h.host, port), payload[:size])
								wantLoss := mode == socks0.ModeEarly && earlyDataLosers[s.Name]
								switch {
								case !wantLoss && err != nil:
									t.Fatal(err)
								case wantLoss && err == nil:
									t.Fatal("early data survived; the server was expected to drop it")
								case wantLoss && !errors.Is(err, errLost):
									t.Fatalf("want lost early data, got %v", err)
								case wantLoss:
									t.Logf("expected incompatibility: %v", err)
								}
							})
						}
					}
				}
			}
		})
	}
}

// TestInteropSocks0Server runs every client in clients.All (L0, L1 and
// L1+L2 alike) through socks0/server: auth × ATYP × payload, echoed by a
// target behind the proxy. Every case must pass: the server keeps
// pipelined and early bytes by construction.
func TestInteropSocks0Server(t *testing.T) {
	i := slices.IndexFunc(servers.All, func(s servers.Server) bool { return s.Name == "socks0/server" })
	if i < 0 {
		t.Fatal("socks0/server not in servers.All")
	}
	s := servers.All[i]
	auths := []struct{ name, user, pass string }{{"noauth", "", ""}, {"userpass", "user", "pass"}}
	hosts := []struct{ name, host string }{{"ipv4", "127.0.0.1"}, {"domain", "localhost"}}
	sizes := []int{64, 1536, 64 << 10}
	payload := make([]byte, 64<<10)
	_, _ = rand.NewChaCha8([32]byte{'s', 'e', 'r', 'v', 'e', 'r'}).Read(payload)

	port := echoTarget(t)
	for _, a := range auths {
		proxy := serveProxy(t, s, a.user, a.pass)
		for _, c := range clients.All {
			for _, h := range hosts {
				for _, size := range sizes {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", c.Name, a.name, h.name, size), func(t *testing.T) {
						t.Parallel()
						ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
						defer cancel()
						_, err := clients.Once(ctx, c, proxy, a.user, a.pass, net.JoinHostPort(h.host, port), payload[:size])
						if err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
	}
}

var errLost = errors.New("lost: head of the payload never reached the target")

// probe is written once the handshake is over, so it reaches the target
// even when the server dropped early data: loss shows without a timeout.
var probe = []byte("\x00socks0 probe\xff")

// echoOnce dials target through d, writes payload, then probe after the
// CONNECT reply, and checks the echo. Writes run concurrently with reads, so
// 64 KiB can't deadlock.
func echoOnce(ctx context.Context, d *socks0.Dialer, target string, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	replied := make(chan struct{})
	ctx = socks0.WithClientTrace(ctx, &socks0.ClientTrace{HandshakeDone: func(error) { close(replied) }})
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)

	written := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		if err == nil {
			select {
			case <-replied: // L2: the first Read consumed the replies
			case <-ctx.Done():
			}
			_, err = c.Write(probe)
		}
		written <- err
	}()
	want := append(bytes.Clone(payload), probe...)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 32<<10)
	for len(got) < len(want) && !bytes.HasSuffix(got, probe) {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			return fmt.Errorf("read after %d/%d bytes: %w", len(got), len(want), err)
		}
	}
	if err := <-written; err != nil {
		return err
	}
	switch {
	case bytes.Equal(got, want):
		return nil
	case len(got) < len(want) && bytes.HasSuffix(want, got):
		return fmt.Errorf("%w: first %d of %d bytes", errLost, len(want)-len(got), len(payload))
	}
	return fmt.Errorf("echo garbled: got %d bytes, want %d", len(got), len(want))
}

// echoTarget serves a TCP echo on 127.0.0.1 and, if possible, ::1 at the
// same port, whichever "localhost" resolves to; it returns the port.
func echoTarget(t *testing.T) string {
	t.Helper()
	for range 100 {
		ln4, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(ln4.Addr().String())
		lns := []net.Listener{ln4}
		if ln6, err := net.Listen("tcp", "[::1]:"+port); err == nil {
			lns = append(lns, ln6)
		} else if !strings.Contains(err.Error(), "cannot assign") && !strings.Contains(err.Error(), "address family") {
			ln4.Close() // port taken on ::1: try another
			continue
		}
		for _, ln := range lns {
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						_, _ = io.Copy(c, c)
					}()
				}
			}()
		}
		return port
	}
	t.Fatal("no free port on both 127.0.0.1 and ::1")
	return ""
}

// serveProxy runs s on a loopback port until the test ends.
func serveProxy(t *testing.T, s servers.Server, user, pass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = s.Serve(ln, user, pass) }()
	return ln.Addr().String()
}

// spyConn records the client's side of the proxy conn: each Write, and
// whether any byte had been read before it.
type spyConn struct {
	net.Conn
	mu     sync.Mutex
	writes []spyWrite
	read   int // bytes read so far
}

type spyWrite struct {
	data      []byte
	afterRead int // bytes read before this write
}

func (c *spyConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, spyWrite{bytes.Clone(p), c.read})
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *spyConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.read += n
	c.mu.Unlock()
	return n, err
}

func (c *spyConn) log() []spyWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// TestHTTPTransportSocks0 sends plain HTTP through http.Transport with a
// socks0 DialContext in each mode, via armon. http.Transport's readLoop
// peeks the conn before writeLoop writes the request; socks0 L2 must wait
// for that Write (the B2 rule) and send handshake + request in one write.
func TestHTTPTransportSocks0(t *testing.T) {
	const body = "hello through socks0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body+" "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "http://")

	for _, a := range []struct{ name, user, pass string }{{"noauth", "", ""}, {"userpass", "user", "pass"}} {
		proxy := serveProxy(t, servers.All[0], a.user, a.pass) // armon
		for _, mode := range socks0Modes {
			t.Run(a.name+"/"+mode.String(), func(t *testing.T) {
				var (
					mu    sync.Mutex
					spies []*spyConn
				)
				cfg := &socks0.Config{Mode: mode}
				if a.user != "" {
					cfg.Auth = socks0.UserPass{Username: a.user, Password: a.pass}
				}
				d := &socks0.Dialer{ProxyAddr: proxy, Config: cfg,
					ProxyDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
						c, err := new(net.Dialer).DialContext(ctx, network, addr)
						if err != nil {
							return nil, err
						}
						s := &spyConn{Conn: c}
						mu.Lock()
						spies = append(spies, s)
						mu.Unlock()
						return s, nil
					}}
				var order orderConn
				tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					c, err := d.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					order.Conn = c
					return &order, nil
				}}
				t.Cleanup(tr.CloseIdleConnections)
				cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}

				for _, path := range []string{"/one", "/two"} { // the second reuses the conn
					resp, err := cl.Get("http://" + target + path)
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil || string(got) != body+" "+path {
						t.Fatalf("GET %s = %q, %v", path, got, err)
					}
				}
				if len(spies) != 1 {
					t.Fatalf("%d proxy dials, want 1 (keep-alive)", len(spies))
				}

				ws := spies[0].log()
				var before []spyWrite // writes before any reply byte was read
				for _, w := range ws {
					if w.afterRead == 0 {
						before = append(before, w)
					}
				}
				reqWrite := slices.IndexFunc(ws, func(w spyWrite) bool { return bytes.Contains(w.data, []byte("GET /one ")) })
				if reqWrite < 0 {
					t.Fatal("request never written")
				}
				t.Logf("%d writes, %d before the first reply byte; request in write #%d (%d B, %d B read before it)",
					len(ws), len(before), reqWrite+1, len(ws[reqWrite].data), ws[reqWrite].afterRead)
				t.Logf("http.Transport called Read before its first Write: %v", order.readFirst.Load())
				switch mode {
				case socks0.ModeEarly:
					// One write before any reply, carrying handshake and request.
					if len(before) != 1 || reqWrite != 0 || ws[0].data[0] != 5 {
						t.Errorf("want handshake + request in the first and only pre-reply write; got %d pre-reply writes, request in #%d", len(before), reqWrite+1)
					}
					if !validRequest(ws[0].data) {
						t.Errorf("first write is not handshake + a parseable request")
					}
				case socks0.ModePipelined:
					if len(before) != 1 || reqWrite != 1 {
						t.Errorf("want 1 handshake write, then the request; got %d pre-reply writes, request in #%d", len(before), reqWrite+1)
					}
				case socks0.ModeSequential:
					want := 2 // greeting, (auth), request
					if a.user != "" {
						want = 3
					}
					if reqWrite != want || len(before) != 1 {
						t.Errorf("want %d handshake writes (1 before any reply), request in #%d; got %d pre-reply, request in #%d", want, want+1, len(before), reqWrite+1)
					}
				}
			})
		}
	}
}

// orderConn records whether Read was entered before the first Write: true
// when http.Transport's readLoop peeks before writeLoop writes.
type orderConn struct {
	net.Conn
	wrote, readFirst atomic.Bool
}

func (c *orderConn) Read(p []byte) (int, error) {
	if !c.wrote.Load() {
		c.readFirst.Store(true)
	}
	return c.Conn.Read(p)
}

func (c *orderConn) Write(p []byte) (int, error) {
	c.wrote.Store(true)
	return c.Conn.Write(p)
}

// validRequest reports whether b is a SOCKS handshake followed by a whole
// HTTP request.
func validRequest(b []byte) bool {
	i := bytes.Index(b, []byte("GET "))
	if i < 0 {
		return false
	}
	_, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[i:])))
	return err == nil
}
