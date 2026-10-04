package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var modes = []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly}

// echoLocalhost listens on both 127.0.0.1 and ::1 at one port.
func echoLocalhost(t testing.TB) string {
	t.Helper()
	lns, port, err := echoListeners("localhost")
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range lns {
		echoOn(t, ln)
	}
	return net.JoinHostPort("localhost", port)
}

func echoOn(t testing.TB, ln net.Listener) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
}

func roundTrip(t testing.TB, c net.Conn, msg []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		got, err := io.ReadAll(c)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo %q, %v; want %q", got, err, msg)
		}
		return
	}
	expect(t, c, msg)
}

func targets(t testing.TB) map[string]string {
	ts := map[string]string{"ipv4": echoTCP(t, "127.0.0.1:0"), "domain": echoLocalhost(t)}
	if hasIPv6() {
		ts["ipv6"] = echoTCP(t, "[::1]:0")
	}
	return ts
}

func TestInteropConnect(t *testing.T) {
	ts := targets(t)
	for _, auth := range []string{"none", "userpass"} {
		s := newServer("", "")
		var cauth socks0.Authenticator
		if auth == "userpass" {
			s = newServer("u", "p")
			cauth = socks0.UserPass{Username: "u", Password: "p"}
		}
		proxy := serve(t, s)
		for _, m := range modes {
			for name, target := range ts {
				t.Run(auth+"/"+m.String()+"/"+name, func(t *testing.T) {
					d := &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Mode: m, Auth: cauth}}
					c, err := d.DialContext(t.Context(), "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					roundTrip(t, c, payload()[:100<<10])
				})
			}
		}
	}
}

func TestInteropConnectErrors(t *testing.T) {
	s := newServer("u", "p")
	s.Handler = &server.ConnectHandler{} // DefaultFilter
	proxy := serve(t, s)
	refused := func() string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		return ln.Addr().String()
	}()
	for _, tt := range []struct {
		name   string
		auth   socks0.Authenticator
		target string
		want   error
		rep    wire.Reply
	}{
		{"loopback", socks0.UserPass{Username: "u", Password: "p"}, "127.0.0.1:80", socks0.ErrNotAllowed, wire.ReplyNotAllowed},
		{"name to loopback", socks0.UserPass{Username: "u", Password: "p"}, "localhost:80", nil, wire.ReplyHostUnreachable},
		{"refused by filter first", socks0.UserPass{Username: "u", Password: "p"}, refused, socks0.ErrNotAllowed, wire.ReplyNotAllowed},
		{"wrong password", socks0.UserPass{Username: "u", Password: "x"}, "192.0.2.1:80", socks0.ErrAuthFailed, 0},
		{"no auth offered", nil, "192.0.2.1:80", socks0.ErrNoAcceptableMethods, 0},
	} {
		for _, m := range modes {
			t.Run(tt.name+"/"+m.String(), func(t *testing.T) {
				d := &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Mode: m, Auth: tt.auth}}
				c, err := d.DialContext(t.Context(), "tcp", tt.target)
				if err == nil {
					if hc, ok := c.(interface{ HandshakeContext(context.Context) error }); ok {
						err = hc.HandshakeContext(t.Context()) // ModeEarly
					}
					c.Close()
				}
				if tt.want != nil && !errors.Is(err, tt.want) {
					t.Fatalf("err %v, want %v", err, tt.want)
				}
				if re, ok := errors.AsType[*socks0.ReplyError](err); tt.rep != 0 && (!ok || re.Reply != tt.rep) {
					t.Fatalf("err %v, want REP %v", err, tt.rep)
				}
			})
		}
	}
}

func TestInteropConnectRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	d := &socks0.Dialer{ProxyAddr: serve(t, open())}
	_, err := d.DialContext(t.Context(), "tcp", addr)
	if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Reply != wire.ReplyConnectionRefused {
		t.Fatalf("err %v, want REP 05", err)
	}
}

func udpServer() *server.Server {
	s := open()
	s.Handler = &server.Mux{Associate: &server.AssociateHandler{Filter: server.AllowAll, Resolver: fakeDNS{"echo.test": "127.0.0.1"}}}
	return s
}

type fakeDNS map[string]string

func (f fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var ips []netip.Addr
	for s := range strings.SplitSeq(f[host], ",") {
		if ip, err := netip.ParseAddr(s); err == nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

func TestInteropUDP(t *testing.T) {
	e1, e2 := echoUDP(t, "127.0.0.1:0"), echoUDP(t, "127.0.0.1:0")
	for _, m := range modes {
		t.Run(m.String(), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: serve(t, udpServer()), Config: &socks0.Config{Mode: m}}
			c, err := d.DialContext(t.Context(), "udp", e1.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			for _, msg := range []string{"ping", "pong", string(payload()[:1400])} {
				if _, err := c.Write([]byte(msg)); err != nil {
					t.Fatal(err)
				}
				expect(t, c, []byte(msg))
			}

			pc, err := d.ListenPacket(t.Context(), "udp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			for _, e := range []*net.UDPConn{e1, e2} {
				if _, err := pc.WriteTo([]byte("to "+e.LocalAddr().String()), e.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 100)
				n, from, err := pc.ReadFrom(b)
				if err != nil || string(b[:n]) != "to "+e.LocalAddr().String() || from.String() != e.LocalAddr().String() {
					t.Fatalf("ReadFrom %q from %v, %v", b[:n], from, err)
				}
			}
			_, port, _ := net.SplitHostPort(e1.LocalAddr().String())
			if _, err := pc.WriteTo([]byte("named"), mustAddr("echo.test:"+port)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 100)
			if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != "named" {
				t.Fatalf("named: %q, %v", b[:n], err)
			}
		})
	}
}

func TestInteropUDPControlClose(t *testing.T) {
	noLeaks(t)
	s := udpServer()
	ended := make(chan error, 1)
	s.Trace = &server.ServerTrace{Done: func(_ context.Context, _ *server.Request, _ server.ConnStats, err error) { ended <- err }}
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	pc, err := d.ListenPacket(t.Context(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	select {
	case err := <-ended:
		if err != nil {
			t.Fatalf("association ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("association outlived its control conn")
	}
}

func TestInteropBind(t *testing.T) {
	s := open()
	s.Handler = &server.Mux{Bind: &server.BindHandler{Filter: server.AllowAll}}
	proxy := serve(t, s)
	for _, m := range modes {
		for _, expectPeer := range []string{"127.0.0.1:0", "", "localhost:0"} {
			t.Run(m.String()+"/"+expectPeer, func(t *testing.T) {
				d := &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Mode: m}}
				ln, err := d.Listen(t.Context(), "tcp", expectPeer)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				peer, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				c, err := ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if got := c.RemoteAddr().String(); got != peer.LocalAddr().String() {
					t.Errorf("peer %v, want %v", got, peer.LocalAddr())
				}
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = peer.Write([]byte("from peer"))
				expect(t, c, []byte("from peer"))
				_, _ = c.Write([]byte("from client"))
				expect(t, peer, []byte("from client"))
			})
		}
	}
}

func TestInteropSOCKS4(t *testing.T) {
	s := open()
	s.Versions = server.V4 | server.V5
	s.Auth = []server.Authenticator{server.UserPass{Users: map[string]string{"u": "p"}}}
	var ids []any
	s.UserID = func(_ context.Context, uid []byte) (any, error) {
		if string(uid) != "alice" {
			return nil, errors.New("unknown user id")
		}
		return "alice", nil
	}
	s.Trace = &server.ServerTrace{GotRequest: func(_ context.Context, r *server.Request) { ids = append(ids, r.Identity, r.Method) }}
	s.Handler = &server.Mux{Connect: &server.ConnectHandler{Filter: server.AllowAll}, Bind: &server.BindHandler{Filter: server.AllowAll}}
	proxy := serve(t, s)
	target := echoTCP(t, "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(target)
	cfg := &socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "alice"}}
	for _, m := range modes {
		for _, tgt := range []string{target, "localhost:" + port} {
			t.Run(m.String()+"/"+tgt, func(t *testing.T) {
				cfg := *cfg
				cfg.Mode = m
				lns, err := net.Listen("tcp", "127.0.0.1:"+port) // localhost may be ::1 first: SOCKS4a resolves at the server
				if err == nil {
					defer lns.Close()
				}
				d := &socks0.Dialer{ProxyAddr: proxy, Config: &cfg}
				c, err := d.DialContext(t.Context(), "tcp", tgt)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				roundTrip(t, c, []byte("socks4"))
			})
		}
	}
	if len(ids) < 2 || ids[0] != "alice" || ids[1] != wire.MethodUserPass {
		t.Errorf("identity/method %v", ids)
	}
	t.Run("bind", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: proxy, Config: cfg}
		ln, err := d.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		peer, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = peer.Write([]byte("hi"))
		expect(t, c, []byte("hi"))
	})
	t.Run("rejected", func(t *testing.T) {
		d := &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "mallory"}}}
		_, err := d.DialContext(t.Context(), "tcp", target)
		if re, ok := errors.AsType[*socks0.ReplyError](err); !ok || re.Version != 4 || re.Reply != wire.Reply4Rejected {
			t.Fatalf("err %v, want 0x5B", err)
		}
	})
}

func TestInteropResolve(t *testing.T) {
	s := open()
	s.Handler = &server.Mux{Resolve: &server.ResolveHandler{Filter: server.AllowAll}}
	d := &socks0.Dialer{ProxyAddr: serve(t, s)}
	ips, err := d.LookupNetIP(t.Context(), "ip", "localhost")
	if err != nil || len(ips) != 1 || !ips[0].IsLoopback() {
		t.Fatalf("LookupNetIP: %v, %v", ips, err)
	}
	names, err := d.LookupAddr(t.Context(), "127.0.0.1")
	if err != nil || len(names) != 1 || names[0] == "" {
		t.Fatalf("LookupAddr: %v, %v", names, err)
	}
	if _, err := d.LookupNetIP(t.Context(), "ip", "nonexistent.invalid"); !isNotFound(err) {
		t.Fatalf("invalid name: %v", err)
	}

	s2 := open()
	s2.Handler = &server.Mux{Resolve: &server.ResolveHandler{}}
	d2 := &socks0.Dialer{ProxyAddr: serve(t, s2)}
	if _, err := d2.LookupNetIP(t.Context(), "ip", "localhost"); !isNotFound(err) {
		t.Fatalf("localhost with DefaultFilter: %v", err)
	}
	if _, err := d2.LookupAddr(t.Context(), "127.0.0.1"); !errors.Is(err, socks0.ErrNotAllowed) {
		t.Fatalf("PTR of loopback with DefaultFilter: %v", err)
	}
	d3 := &socks0.Dialer{ProxyAddr: serve(t, open())}
	if _, err := d3.LookupNetIP(t.Context(), "ip", "localhost"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("ConnectHandler: %v", err)
	}
	d3 = &socks0.Dialer{ProxyAddr: serve(t, &server.Server{})}
	if _, err := d3.LookupNetIP(t.Context(), "ip", "localhost"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("no handler: %v", err)
	}
}

func isNotFound(err error) bool {
	de, ok := errors.AsType[*net.DNSError](err)
	return ok && de.IsNotFound
}

func selfSigned(t testing.TB) (srv, cli *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		&tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}
}

// No splice through TLS; CloseWrite is close_notify.
func TestInteropTLS(t *testing.T) {
	srvCfg, cliCfg := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newServer("u", "p")
	go func() { _ = s.Serve(tls.NewListener(ln, srvCfg)) }()
	t.Cleanup(func() { s.Close() })
	target := echoTCP(t, "127.0.0.1:0")
	td := &tls.Dialer{Config: cliCfg}
	for _, m := range modes {
		t.Run(m.String(), func(t *testing.T) {
			d := &socks0.Dialer{ProxyAddr: ln.Addr().String(), ProxyDial: td.DialContext,
				Config: &socks0.Config{Mode: m, Auth: socks0.UserPass{Username: "u", Password: "p"}}}
			c, err := d.DialContext(t.Context(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			roundTrip(t, c, payload()[:200<<10])
		})
	}
}

// BIND's early data must reach the peer.
func TestPipelinedBindAndUDP(t *testing.T) {
	s := open()
	s.Handler = &server.Mux{
		Bind:      &server.BindHandler{Filter: server.AllowAll},
		Associate: &server.AssociateHandler{Filter: server.AllowAll},
	}
	proxy := serve(t, s)

	c := dial(t, proxy)
	_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "0.0.0.0:0"), []byte("early to peer")))
	expect(t, c, []byte{5, 0})
	_, bound := readReply(t, c, wire.CmdBind)
	peer, err := net.Dial("tcp", bound.String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if rep, from := readReply(t, c, wire.CmdBind); rep != 0 || from.String() != peer.LocalAddr().String() {
		t.Fatalf("second reply %v %v", rep, from)
	}
	expect(t, peer, []byte("early to peer"))

	u := dial(t, proxy)
	_, _ = u.Write(cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")))
	expect(t, u, []byte{5, 0})
	_, relay := readReply(t, u, wire.CmdUDPAssociate)
	e := echoUDP(t, "127.0.0.1:0")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	hdr, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(e.LocalAddr().(*net.UDPAddr).AddrPort()))
	ra := net.UDPAddrFromAddrPort(netip.AddrPortFrom(relay.IP(), relay.Port()))
	_, _ = pc.WriteTo(cat(hdr, []byte("dgram")), ra)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 100)
	n, _, err := pc.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], cat(hdr, []byte("dgram"))) {
		t.Fatalf("relayed %x, %v", b[:n], err)
	}
	if !slices.Equal(b[:3], []byte{0, 0, 0}) {
		t.Fatal("header")
	}
}
