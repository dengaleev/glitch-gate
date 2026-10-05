package server_test

// CONNECT, end to end with the socks0 client, and the replies for dial errors.

import (
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
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var modes = []socks0.Mode{socks0.ModeSequential, socks0.ModePipelined, socks0.ModeEarly}

// Every mode, auth and ATYP, also with the proxy behind TLS (no splice; CloseWrite is close_notify).
func TestInteropConnect(t *testing.T) {
	ts := map[string]string{"ipv4": echoTCP(t, "127.0.0.1:0"), "domain": echoLocalhost(t)}
	if hasIPv6() {
		ts["ipv6"] = echoTCP(t, "[::1]:0")
	}
	srvTLS, cliTLS := selfSigned(t)
	up := socks0.UserPass{Username: "u", Password: "p"}
	for _, auth := range []string{"none", "userpass", "userpass+TLS"} {
		var cauth socks0.Authenticator
		var proxyDial func(context.Context, string, string) (net.Conn, error)
		var proxy string
		switch auth {
		case "none":
			proxy = serve(t, newServer("", ""))
		case "userpass":
			proxy, cauth = serve(t, newServer("u", "p")), up
		default:
			proxy, cauth = serveLn(t, newServer("u", "p"), tls.NewListener(listenLoopback(t), srvTLS)), up
			proxyDial = (&tls.Dialer{Config: cliTLS}).DialContext
		}
		for _, m := range modes {
			for name, target := range ts {
				t.Run(auth+"/"+m.String()+"/"+name, func(t *testing.T) {
					d := &socks0.Dialer{ProxyAddr: proxy, ProxyDial: proxyDial, Config: &socks0.Config{Mode: m, Auth: cauth}}
					c, err := d.DialContext(t.Context(), "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					roundTrip(t, c, payload()[:200<<10])
				})
			}
		}
	}
}

func TestInteropConnectErrors(t *testing.T) {
	filtered := newServer("u", "p")
	filtered.Handler = &server.ConnectHandler{} // DefaultFilter
	proxies := map[bool]string{true: serve(t, filtered), false: serve(t, open())}
	refused := func() string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		return ln.Addr().String()
	}()
	up := socks0.UserPass{Username: "u", Password: "p"}
	for _, tt := range []struct {
		name     string
		filtered bool
		auth     socks0.Authenticator
		target   string
		want     error
		rep      wire.Reply
	}{
		{"loopback", true, up, "127.0.0.1:80", socks0.ErrNotAllowed, wire.ReplyNotAllowed},
		{"name to loopback", true, up, "localhost:80", nil, wire.ReplyHostUnreachable},
		{"refused by filter first", true, up, refused, socks0.ErrNotAllowed, wire.ReplyNotAllowed},
		{"wrong password", true, socks0.UserPass{Username: "u", Password: "x"}, "192.0.2.1:80", socks0.ErrAuthFailed, 0},
		{"no auth offered", true, nil, "192.0.2.1:80", socks0.ErrNoAcceptableMethods, 0},
		{"refused", false, nil, refused, nil, wire.ReplyConnectionRefused},
	} {
		for _, m := range modes {
			t.Run(tt.name+"/"+m.String(), func(t *testing.T) {
				d := &socks0.Dialer{ProxyAddr: proxies[tt.filtered], Config: &socks0.Config{Mode: m, Auth: tt.auth}}
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

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }

func TestReplyFor(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want wire.Reply
	}{
		{nil, 0}, {&socks0.ReplyError{Reply: 0xF6}, 0xF6}, {&net.OpError{Err: &socks0.ReplyError{Reply: 5}}, 5},
		{&socks0.ReplyError{Reply: 0x5B, Version: 4}, 1}, {&socks0.ReplyError{Reply: 0x5C, Version: 4}, 2},
		{&socks0.ReplyError{Reply: 0x5D, Version: 4}, 2}, {&server.DeniedError{}, 2}, {errors.Join(io.EOF, server.ErrNotAllowed), 2},
		{errors.ErrUnsupported, 7}, {&net.DNSError{Err: "x"}, 4}, {context.DeadlineExceeded, 6},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, 6}, {context.Canceled, 1}, {io.EOF, 1},
	} {
		if got := server.ReplyFor(tt.err); got != tt.want {
			t.Errorf("ReplyFor(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
	for _, tt := range errnoReplies() {
		if got := server.ReplyFor(&net.OpError{Op: "dial", Err: tt.err}); got != tt.want {
			t.Errorf("ReplyFor(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
