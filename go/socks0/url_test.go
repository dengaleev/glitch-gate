package socks0_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

func TestParseProxyURL(t *testing.T) {
	long := strings.Repeat("x", 256)
	for _, tt := range []struct {
		in   string
		want *socks0.ProxyURL // nil: an error
	}{
		{"socks5://proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", ResolveLocally: true}},
		{"SOCKS5H://proxy.example:9050", &socks0.ProxyURL{Addr: "proxy.example:9050"}},
		{"socks5h://[2001:db8::1]:1", &socks0.ProxyURL{Addr: "[2001:db8::1]:1"}},
		{"socks5s://proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", TLS: true}},
		{"socks5+tls://proxy.example:443/path?q#f", &socks0.ProxyURL{Addr: "proxy.example:443", TLS: true}},
		{"socks5h+tls://proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", TLS: true}},
		{"socks5://user:p%40ss@proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", ResolveLocally: true,
			Config: socks0.Config{Auth: socks0.UserPass{Username: "user", Password: "p@ss"}}}},
		{"socks5h://@proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", Config: socks0.Config{Auth: socks0.UserPass{}}}},
		{"socks5h://u@proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", Config: socks0.Config{Auth: socks0.UserPass{Username: "u"}}}},
		{"socks4://proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", ResolveLocally: true, Config: socks0.Config{Version: 4}}},
		{"socks4a://u@proxy.example", &socks0.ProxyURL{Addr: "proxy.example:1080", Config: socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "u"}}}},
		{"socks4a://u:p@proxy.example", nil},
		{"socks4h://proxy.example", nil},
		{"http://proxy.example", nil},
		{"socks5:proxy.example:1080", nil},
		{"socks5://", nil},
		{"socks5://:1080", nil},
		{"socks5://proxy.example:0", nil},
		{"socks5://proxy.example:65536", nil},
		{"socks5://" + long + ":secret@proxy.example", nil},
		{"socks5://u:" + long + "@proxy.example", nil},
	} {
		u, err := url.Parse(tt.in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := socks0.ParseProxyURL(u)
		if !reflect.DeepEqual(got, tt.want) || (err == nil) != (tt.want != nil) {
			t.Errorf("ParseProxyURL(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
		if err != nil && (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), long+"@")) {
			t.Errorf("error holds the password: %v", err)
		}
	}
	if _, err := socks0.ParseProxyURL(nil); err == nil {
		t.Error("nil URL")
	}
	// Opaque URLs built by hand.
	if _, err := socks0.ParseProxyURL(&url.URL{Scheme: "socks5", Opaque: "x", Host: "h"}); err == nil {
		t.Error("opaque URL")
	}
}

func TestFromURL(t *testing.T) {
	d, err := socks0.FromURL(&url.URL{Scheme: "socks5", Host: "proxy.example", User: url.UserPassword("u", "p")})
	if err != nil {
		t.Fatal(err)
	}
	if d.ProxyAddr != "proxy.example:1080" || d.Resolver != net.DefaultResolver || d.ProxyDial != nil ||
		d.Config.Auth != (socks0.UserPass{Username: "u", Password: "p"}) {
		t.Errorf("socks5: %+v", d)
	}
	d, _ = socks0.FromURL(&url.URL{Scheme: "socks5h", Host: "proxy.example"})
	if d.Resolver != nil || d.ProxyDial != nil || d.Config.Auth != nil {
		t.Errorf("socks5h: %+v", d)
	}
	if _, err := socks0.FromURL(&url.URL{Scheme: "http", Host: "proxy.example"}); err == nil {
		t.Error("http accepted")
	}
}

func TestProxyTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	addr := listen(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: srv.TLS.Certificates})
		defer tc.Close()
		proxy{}.serve(tc)
	})

	d, err := socks0.FromURL(&url.URL{Scheme: "socks5s", Host: addr})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(t.Context(), "tcp", "example.com:80")
	if he := handshakeErrOf(t, err); he.Stage != socks0.StageProxyDial {
		t.Fatalf("err = %v", err)
	}
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
		t.Errorf("err = %v; want an unknown authority", err)
	}

	p, err := socks0.ParseProxyURL(&url.URL{Scheme: "socks5+tls", Host: addr})
	if err != nil {
		t.Fatal(err)
	}
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	d = &socks0.Dialer{ProxyAddr: p.Addr, Config: &p.Config, ProxyDial: (&tls.Dialer{Config: &tls.Config{RootCAs: pool}}).DialContext}
	c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(*tls.Conn); !ok {
		t.Errorf("conn is %T", c)
	}
	c.Write([]byte("tls"))
	if s := readN(t, c, 3); s != "tls" {
		t.Errorf("echo %q", s)
	}
}
