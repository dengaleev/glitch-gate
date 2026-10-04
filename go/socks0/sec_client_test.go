package socks0_test

// TestSec_* pin fixed review findings; TestSecOK_* properties that already held.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Finding L1.
func TestSec_ClientFmtRedactsPassword(t *testing.T) {
	u, _ := url.Parse("socks5h://alice:hunter2@proxy.example:1080")
	p, err := socks0.ParseProxyURL(u)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := socks0.FromURL(u)
	up := p.Config.Auth.(socks0.UserPass)
	cfgPtr := &socks0.Config{Auth: &up}
	custom := socks0.Config{Auth: tokenAuth("s3cr3t-token")}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("dial", "url", p, "cfg", d.Config, "auth", up, "ptr", cfgPtr, "custom", custom)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("dial", "url", p, "cfg", d.Config, "auth", up, "ptr", cfgPtr, "custom", custom)
	if !strings.Contains(js.String(), `"custom":{"version":0,"mode":"pipelined","auth":"0x80"`) || strings.Contains(js.String(), "s3cr3t-token") {
		t.Errorf("custom Authenticator in slog: %s", js.String())
	}
	outs := map[string]string{
		"%v ProxyURL": fmt.Sprintf("%v", p), "%+v ProxyURL": fmt.Sprintf("%+v", p), "%#v ProxyURL": fmt.Sprintf("%#v", p),
		"%v Config": fmt.Sprintf("%v", *d.Config), "%+v *Config": fmt.Sprintf("%+v", d.Config), "%#v Config": fmt.Sprintf("%#v", *d.Config),
		"%v UserPass": fmt.Sprintf("%v", up), "%+v UserPass": fmt.Sprintf("%+v", up), "%#v UserPass": fmt.Sprintf("%#v", up),
		"%s": fmt.Sprintf("%s", up), "%q": fmt.Sprintf("%q", up), "%x": fmt.Sprintf("%x", up), "%d": fmt.Sprintf("%d", up),
		"%+v *UserPass in Config": fmt.Sprintf("%+v", *cfgPtr), "%#v *UserPass in Config": fmt.Sprintf("%#v", *cfgPtr),
		"%+v *Dialer": fmt.Sprintf("%+v", d),
		"err":         fmt.Sprint(func() error { _, err := d.DialContext(canceled(), "tcp", "x:1"); return err }()),
		"slog text":   text.String(), "slog json": js.String(),
	}
	for k, v := range outs {
		if strings.Contains(v, "hunter2") || strings.Contains(v, "68756e74") {
			t.Errorf("%s leaks the password: %s", k, v)
		}
	}
	if !strings.Contains(outs["%v UserPass"], "alice") || !strings.Contains(outs["slog json"], `"username":"alice"`) {
		t.Errorf("user name lost: %s / %s", outs["%v UserPass"], outs["slog json"])
	}
}

// tokenAuth holds a secret and has no LogValue.
type tokenAuth string

func (tokenAuth) Method() wire.Method                               { return 0x80 }
func (tokenAuth) Authenticate(context.Context, io.ReadWriter) error { return nil }

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func selfSigned(t *testing.T, host string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{host}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestSecOK_TLSSchemesVerify(t *testing.T) {
	cert := selfSigned(t, "localhost")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				b, err := io.ReadAll(c)
				got <- fmt.Sprintf("%q %v", b, err)
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, raw := range []string{
		"socks5s://alice:hunter2@127.0.0.1:" + port,
		"socks5+tls://alice:hunter2@localhost:" + port,
		"socks5h+tls://alice:hunter2@localhost:" + port,
	} {
		u, _ := url.Parse(raw)
		d, err := socks0.FromURL(u)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = d.DialContext(ctx, "tcp", "example.com:80")
		cancel()
		if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
			t.Fatalf("%s: want x509 unknown authority, got %v", raw, err)
		}
		if s := <-got; strings.Contains(s, "hunter2") {
			t.Fatalf("credentials reached impostor: %s", s)
		}
	}
}

func tarpit(t *testing.T) string {
	t.Helper()
	return listen(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
}

// Finding L11.
func TestSec_ClientHandshakeTimeout(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		errStop := errors.New("stop")
		for _, tc := range []struct {
			name   string
			hst    time.Duration
			ctx    time.Duration // ctx deadline from now; zero: none
			want   time.Duration // ProxyDial's ctx deadline from now; zero: none
			dialFn func(d *socks0.Dialer, ctx context.Context) error
		}{
			{name: "Dial", want: 30 * time.Second},
			{name: "Dial ctx deadline kept", ctx: time.Hour, want: time.Hour},
			{name: "Dial explicit", hst: 5 * time.Second, want: 5 * time.Second},
			{name: "Dial explicit, earlier ctx", hst: 5 * time.Second, ctx: 2 * time.Second, want: 2 * time.Second},
			{name: "Dial none", hst: -1},
			{name: "Listen", want: 30 * time.Second, dialFn: func(d *socks0.Dialer, ctx context.Context) error { _, err := d.Listen(ctx, "tcp", ""); return err }},
			{name: "ListenUDP", want: 30 * time.Second, dialFn: func(d *socks0.Dialer, ctx context.Context) error { _, err := d.ListenUDP(ctx, "udp", ""); return err }},
			{name: "LookupNetIP", want: 30 * time.Second, dialFn: func(d *socks0.Dialer, ctx context.Context) error {
				_, err := d.LookupNetIP(ctx, "ip", "x.test")
				return err
			}},
		} {
			for _, mode := range []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly} {
				var dl time.Time
				var has bool
				d := &socks0.Dialer{ProxyAddr: "proxy.test:1080", Config: &socks0.Config{Mode: mode, HandshakeTimeout: tc.hst},
					ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						dl, has = ctx.Deadline()
						return nil, errStop
					}}
				ctx := context.Background()
				if tc.ctx > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.ctx)
					defer cancel()
				}
				f := tc.dialFn
				if f == nil {
					f = func(d *socks0.Dialer, ctx context.Context) error {
						_, err := d.DialContext(ctx, "tcp", "x.test:80")
						return err
					}
				}
				if err := f(d, ctx); !errors.Is(err, errStop) {
					t.Fatalf("%s %v: %v", tc.name, mode, err)
				}
				left := time.Until(dl)
				if has != (tc.want > 0) || has && (left > tc.want || left < tc.want-5*time.Second) {
					t.Errorf("%s %v: ProxyDial ctx deadline in %v (set %v), want %v", tc.name, mode, left, has, tc.want)
				}
			}
		}
	})

	t.Run("tarpit", func(t *testing.T) {
		proxy := tarpit(t)
		within := func(name string, f func() error) {
			t.Helper()
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- f() }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) && socks0.KindOf(err) != socks0.KindTimeout {
					t.Errorf("%s: %v (kind %s), want a timeout", name, err, socks0.KindOf(err))
				}
				if el := time.Since(start); el > 3*time.Second {
					t.Errorf("%s: took %v", name, el)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: still blocked after 10 s", name)
			}
		}
		for _, mode := range []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly} {
			cfg := &socks0.Config{Mode: mode, HandshakeTimeout: 200 * time.Millisecond}
			d := &socks0.Dialer{ProxyAddr: proxy, Config: cfg}
			within(fmt.Sprint("Dialer ", mode), func() error {
				c, err := d.Dial("tcp", "example.com:80")
				if err == nil { // ModeEarly: the reply wait, after the first Write
					defer c.Close()
					if _, err = c.Write([]byte("x")); err == nil {
						_, err = c.Read(make([]byte, 1))
					}
				}
				return err
			})
			for _, op := range []string{"Read", "Write", "HandshakeContext"} {
				if op == "Read" && mode == socks0.ModeEarly {
					continue // a Read before the first Write waits for it, by design
				}
				within(fmt.Sprint("Client ", mode, " ", op), func() error {
					nc, err := net.Dial("tcp", proxy)
					if err != nil {
						return err
					}
					c := socks0.Client(nc, "example.com:80", cfg)
					defer c.Close()
					switch op {
					case "Read":
						_, err = c.Read(make([]byte, 1))
					case "Write":
						if _, err = c.Write([]byte("x")); err == nil {
							_, err = c.Read(make([]byte, 1)) // ModeEarly writes without waiting
						}
					default:
						err = c.HandshakeContext(context.Background())
					}
					return err
				})
			}
		}
		// ModeEarly: ReplyTimeout wins over HandshakeTimeout.
		d := &socks0.Dialer{ProxyAddr: proxy, Config: &socks0.Config{Mode: socks0.ModeEarly, ReplyTimeout: 200 * time.Millisecond, HandshakeTimeout: time.Hour}}
		within("ReplyTimeout wins", func() error {
			c, err := d.Dial("tcp", "example.com:80")
			if err != nil {
				return err
			}
			defer c.Close()
			return c.(*socks0.Conn).HandshakeContext(context.Background())
		})
	})
}

// hostileBNDProxy answers one UDP ASSOCIATE with BND bnd and keeps the control conn open.
func hostileBNDProxy(t *testing.T, bnd wire.Addr) string {
	t.Helper()
	return listen(t, func(c net.Conn) {
		if _, err := wire.ReadGreeting(c); err != nil {
			return
		}
		if _, _, err := wire.ReadRequest(c); err != nil {
			return
		}
		rep, _ := wire.AppendReply(wire.AppendMethodSelection(nil, wire.MethodNoAuth), wire.ReplySucceeded, bnd)
		_, _ = c.Write(rep)
		_, _ = io.Copy(io.Discard, c)
	})
}

// Finding L2. RelayUseProxyHost is the way out for a NATed proxy's private BND.
func TestSec_ClientUDPRejectsHostileBND(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	port := uint16(sink.LocalAddr().(*net.UDPAddr).Port)
	bnd := func(s string) wire.Addr { return mustAddr(net.JoinHostPort(s, fmt.Sprint(port))) }
	for _, tc := range []struct {
		proxyIP   string // the proxy's IP (ProxyAddr), reached through ProxyDial
		bnd       wire.Addr
		proxyHost bool
		ok        bool
	}{
		{proxyIP: "192.0.2.10", bnd: bnd("127.0.0.1")},
		{proxyIP: "192.0.2.10", bnd: bnd("::1")},
		{proxyIP: "192.0.2.10", bnd: bnd("::ffff:127.0.0.1")},
		{proxyIP: "192.0.2.10", bnd: bnd("localhost")},
		{proxyIP: "192.0.2.10", bnd: bnd("255.255.255.255")},
		{proxyIP: "192.0.2.10", bnd: bnd("224.0.0.251")},
		{proxyIP: "192.0.2.10", bnd: bnd("ff02::fb")},
		{proxyIP: "192.0.2.10", bnd: bnd("10.1.2.3")},
		{proxyIP: "192.0.2.10", bnd: bnd("100.64.1.1")},
		{proxyIP: "192.0.2.10", bnd: bnd("169.254.169.254")},
		{proxyIP: "192.0.2.10", bnd: bnd("fd00::1")},
		{proxyIP: "10.0.0.5", bnd: bnd("127.0.0.1")},
		{proxyIP: "10.0.0.5", bnd: bnd("169.254.169.254")},
		{proxyIP: "192.0.2.10", bnd: bnd("10.1.2.3"), proxyHost: true, ok: true},
		{proxyIP: "192.0.2.10", bnd: bnd("0.0.0.0"), ok: true},
		{proxyIP: "192.0.2.10", bnd: bnd("198.51.100.7"), ok: true},
		{proxyIP: "10.0.0.5", bnd: bnd("192.168.1.1"), ok: true},
		{proxyIP: "127.0.0.1", bnd: bnd("10.1.2.3"), ok: true},
		{proxyIP: "127.0.0.1", bnd: bnd("127.0.0.1"), ok: true},
	} {
		proxy := hostileBNDProxy(t, tc.bnd)
		d := &socks0.Dialer{
			ProxyAddr: net.JoinHostPort(tc.proxyIP, "1080"),
			ProxyDial: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, n, proxy)
			},
			RelayUseProxyHost: tc.proxyHost,
		}
		c, err := d.DialContext(t.Context(), "udp", "9.9.9.9:53")
		if tc.ok {
			if err != nil {
				t.Errorf("proxy %s, BND %v: %v", tc.proxyIP, tc.bnd, err)
			} else {
				c.Close()
			}
			continue
		}
		if err == nil {
			_, _ = c.Write([]byte("private-dns-query"))
			c.Close()
			t.Errorf("proxy %s, BND %v: association opened", tc.proxyIP, tc.bnd)
			continue
		}
		he, _ := errors.AsType[*socks0.HandshakeError](err)
		if he == nil || he.Stage != socks0.StageRelayDial || socks0.KindOf(err) != socks0.KindDenied ||
			!errors.Is(err, socks0.ErrNotAllowed) || !strings.Contains(err.Error(), "relay address refused") {
			t.Errorf("proxy %s, BND %v: %v (kind %s)", tc.proxyIP, tc.bnd, err, socks0.KindOf(err))
		}
	}
	_ = sink.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := sink.ReadFrom(make([]byte, 100)); err == nil {
		t.Fatalf("a %d-byte datagram reached the client's loopback service", n)
	}
}

// Finding L4: DST.PORT makes the server drop datagrams forged from another port.
func TestSec_AssociateLocalPort(t *testing.T) {
	echoAP := udpServe(t, "udp4", echo)
	var mu sync.Mutex
	var dst wire.Addr
	var drops []string
	s := &server.Server{
		Handler: &server.AssociateHandler{Filter: server.AllowAll},
		Trace: &server.ServerTrace{
			GotRequest: func(_ context.Context, r *server.Request) { mu.Lock(); dst = r.Addr; mu.Unlock() },
			Dropped: func(_ context.Context, from netip.AddrPort, err error) {
				mu.Lock()
				drops = append(drops, err.Error())
				mu.Unlock()
			},
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	defer s.Close()

	for _, listen := range []bool{false, true} {
		d := &socks0.Dialer{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true}
		if listen {
			d.RelayListen = new(net.ListenConfig).ListenPacket
		}
		c, err := d.DialContext(t.Context(), "udp", echoAP.String())
		if err != nil {
			t.Fatal(err)
		}
		uc := c.(*socks0.UDPConn)
		lport := uc.LocalAddr().(*net.UDPAddr).Port
		mu.Lock()
		got := dst
		mu.Unlock()
		if !got.IP().IsUnspecified() || int(got.Port()) != lport {
			t.Fatalf("RelayListen %v: DST %v, relay socket port %d", listen, got, lport)
		}
		attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		relay := uc.RelayAddr().(*net.UDPAddr).AddrPort()
		h, _ := wire.AppendUDPHeader(nil, 0, wire.AddrFromAddrPort(echoAP))
		_, _ = attacker.WriteToUDPAddrPort(append(h, "forged"...), relay)
		attacker.Close()
		time.Sleep(50 * time.Millisecond)
		if s := roundTrip(t, c, "hi"); s != "hi" {
			t.Fatalf("echo %q", s)
		}
		c.Close()
		mu.Lock()
		if len(drops) != 1 || !strings.Contains(drops[0], "another source") {
			t.Fatalf("drops %q", drops)
		}
		drops = nil
		mu.Unlock()
	}
	// RelayListen failures fail the association before the request.
	errListen := errors.New("listen failed")
	for _, l := range []func(context.Context, string, string) (net.PacketConn, error){
		func(context.Context, string, string) (net.PacketConn, error) { return nil, errListen },
		func(context.Context, string, string) (net.PacketConn, error) { return nil, nil },
		func(ctx context.Context, n, a string) (net.PacketConn, error) {
			pc, err := new(net.ListenConfig).ListenPacket(ctx, n, a)
			return pc, errors.Join(err, errListen)
		},
		func(context.Context, string, string) (net.PacketConn, error) { return pipePacketConn{}, nil },
	} {
		d := &socks0.Dialer{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true, RelayListen: l}
		_, err := d.DialContext(t.Context(), "udp", echoAP.String())
		if he, ok := errors.AsType[*socks0.HandshakeError](err); !ok || he.Stage != socks0.StageRelayDial {
			t.Errorf("RelayListen failing: %v", err)
		}
	}
	// Not with RelayDial or an explicit DST: nothing to bind first.
	for _, d := range []*socks0.Dialer{
		{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true, RelayDial: new(net.Dialer).DialContext},
		{ProxyAddr: ln.Addr().String(), AssociateLocalPort: true, AssociateAddr: "192.0.2.1:0"},
	} {
		if _, err := d.DialContext(t.Context(), "udp", echoAP.String()); socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("%+v: %v", d, err)
		}
	}
}

type pipePacketConn struct{ net.PacketConn }

func (pipePacketConn) LocalAddr() net.Addr { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (pipePacketConn) Close() error        { return nil }

// wireRec keeps the slices passed to Write (not copies) to inspect client buffers.
type wireRec struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *wireRec) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *wireRec) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

// Best effort: the strings in Config stay.
func TestSec_ClientWipesCredentials(t *testing.T) {
	target := listen(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	s := &server.Server{
		Auth:    []server.Authenticator{server.UserPass{Users: map[string]string{"alice": "hunter2"}}},
		Handler: &server.ConnectHandler{Filter: server.AllowAll},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	defer s.Close()
	for _, mode := range []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly} {
		for _, auth := range []socks0.Authenticator{socks0.UserPass{Username: "alice", Password: "hunter2"}, &socks0.UserPass{Username: "alice", Password: "hunter2"}} {
			var rec *wireRec
			d := &socks0.Dialer{ProxyAddr: ln.Addr().String(), Config: &socks0.Config{Mode: mode, Auth: auth},
				ProxyDial: func(ctx context.Context, n, a string) (net.Conn, error) {
					c, err := new(net.Dialer).DialContext(ctx, n, a)
					if err == nil {
						rec = &wireRec{Conn: c}
						return rec, nil
					}
					return nil, err
				}}
			c, err := d.DialContext(t.Context(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			if b := make([]byte, 4); func() error { _, err := io.ReadFull(c, b); return err }() != nil || string(b) != "ping" {
				t.Fatalf("%v: echo %q", mode, b)
			}
			c.Close()
			rec.mu.Lock()
			for _, w := range rec.writes {
				if bytes.Contains(w, []byte("hunter2")) {
					t.Errorf("%v %T: the password is still in a written buffer: %q", mode, auth, w)
				}
			}
			rec.mu.Unlock()
		}
	}
}
