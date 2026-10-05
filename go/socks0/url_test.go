package socks0_test

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
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// ParseProxyURL and FromURL agree; errors never hold the credentials.
func TestParseProxyURL(t *testing.T) {
	long := strings.Repeat("x", 256)
	up := func(u, p string) socks0.Config { return socks0.Config{Auth: socks0.UserPass{Username: u, Password: p}} }
	for _, tt := range []struct {
		in     string
		want   *socks0.ProxyURL // nil: an error
		secret string           // not in an error
	}{
		{in: "socks5://proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", ResolveLocally: true}},
		{in: "SOCKS5H://proxy.example:9050", want: &socks0.ProxyURL{Addr: "proxy.example:9050"}},
		{in: "socks5h://[2001:db8::1]:1", want: &socks0.ProxyURL{Addr: "[2001:db8::1]:1"}},
		{in: "socks5://[::1]", want: &socks0.ProxyURL{Addr: "[::1]:1080", ResolveLocally: true}},
		{in: "socks5://h:65535", want: &socks0.ProxyURL{Addr: "h:65535", ResolveLocally: true}},
		{in: "socks5h://h:0080", want: &socks0.ProxyURL{Addr: "h:80"}},
		{in: "socks5s://proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", TLS: true}},
		{in: "socks5+tls://proxy.example:443/path?q#f", want: &socks0.ProxyURL{Addr: "proxy.example:443", TLS: true}},
		{in: "socks5h+tls://proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", TLS: true}},
		{in: "socks5://user:p%40ss@proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", ResolveLocally: true, Config: up("user", "p@ss")}},
		{in: "socks5://u:p%40ss%3Aw@h", want: &socks0.ProxyURL{Addr: "h:1080", ResolveLocally: true, Config: up("u", "p@ss:w")}},
		{in: "socks5://%75ser@h", want: &socks0.ProxyURL{Addr: "h:1080", ResolveLocally: true, Config: up("user", "")}},
		{in: "socks5h://@proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", Config: up("", "")}},
		{in: "socks5://:@h", want: &socks0.ProxyURL{Addr: "h:1080", ResolveLocally: true, Config: up("", "")}},
		{in: "socks5h://u@proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", Config: up("u", "")}},
		{in: "socks4://proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", ResolveLocally: true, Config: socks0.Config{Version: 4}}},
		{in: "socks4://user@proxy:1081", want: &socks0.ProxyURL{Addr: "proxy:1081", ResolveLocally: true, Config: socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "user"}}}},
		{in: "SOCKS4A://proxy", want: &socks0.ProxyURL{Addr: "proxy:1080", Config: socks0.Config{Version: 4}}},
		{in: "socks4a://u@proxy.example", want: &socks0.ProxyURL{Addr: "proxy.example:1080", Config: socks0.Config{Version: 4, Auth: socks0.UserPass{Username: "u"}}}},
		{in: "socks4a://u:topsecret@proxy.example", secret: "topsecret"},
		{in: "socks4h://proxy.example"},
		{in: "http://proxy.example"},
		{in: "socks://h"},
		{in: "h:1080"},
		{in: "socks5:proxy.example:1080"},
		{in: "socks5://"},
		{in: "socks5:///path"},
		{in: "socks5://:1080"},
		{in: "socks5://proxy.example:0"},
		{in: "socks5://proxy.example:65536"},
		{in: "socks5://h:99999999999999999999"},
		{in: "socks5://" + long + ":topsecret@proxy.example", secret: "topsecret"},
		{in: "socks5://u:" + long + "@proxy.example", secret: long},
		{in: "ftp://u:topsecret@h", secret: "topsecret"},
		{in: "socks5://u:topsecret@h:0", secret: "topsecret"},
		{in: "socks5://u:topsecret@:1", secret: "topsecret"},
		{in: "socks5://topuser:pw@h:0", secret: "topuser"},
		{in: "socks5:topuser:pw@h:1", secret: "topuser"},
		// An opaque URL (no "//") holds the password in Opaque, which u.Redacted keeps.
		{in: "socks5:user:hunter2secret@proxy.example:1080", secret: "hunter2secret"},
		{in: "http:user:hunter2secret@proxy.example:1080", secret: "hunter2secret"},
	} {
		u, err := url.Parse(tt.in)
		if err != nil {
			if tt.want != nil {
				t.Errorf("%s: url.Parse: %v", tt.in, err)
			}
			continue
		}
		got, err := socks0.ParseProxyURL(u)
		if !reflect.DeepEqual(got, tt.want) || (err == nil) != (tt.want != nil) {
			t.Errorf("ParseProxyURL(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
		d, derr := socks0.FromURL(u)
		if err != nil {
			if derr == nil {
				t.Errorf("FromURL(%q) succeeded", tt.in)
			}
			for _, e := range []error{err, derr} {
				if e != nil && tt.secret != "" && strings.Contains(e.Error(), tt.secret) {
					t.Errorf("%s: error holds the credential: %v", tt.in, e)
				}
			}
			continue
		}
		var res socks0.Resolver
		if got.ResolveLocally {
			res = net.DefaultResolver
		}
		if derr != nil || d.ProxyAddr != got.Addr || d.Resolver != res || (d.ProxyDial != nil) != got.TLS || d.Config == nil || !reflect.DeepEqual(*d.Config, got.Config) {
			t.Errorf("FromURL(%q) = %+v, %v", tt.in, d, derr)
		}
	}
	// url.Parse accepts hosts like "]0": an accepted one must give a usable Addr.
	if u, err := url.Parse("socks5://]0"); err == nil {
		if p, err := socks0.ParseProxyURL(u); err == nil {
			if _, _, err := net.SplitHostPort(p.Addr); err != nil {
				t.Errorf("accepted host %q gives unusable Addr %q: %v", u.Host, p.Addr, err)
			}
		}
	}
	for _, u := range []*url.URL{nil, {}, {Scheme: "socks5", Opaque: "x", Host: "h"}} {
		if _, err := socks0.ParseProxyURL(u); err == nil {
			t.Errorf("ParseProxyURL(%#v): no error", u)
		}
	}
	if _, err := socks0.FromURL(nil); err == nil {
		t.Error("FromURL(nil)")
	}
}

// The TLS schemes verify the proxy's certificate: an impostor gets no credential.
func TestProxyTLS(t *testing.T) {
	// A self-signed certificate for localhost and 127.0.0.1.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der := must(x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k))
	got := make(chan string, 4)
	addr := listen(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
		defer tc.Close()
		if err := tc.Handshake(); err != nil {
			b, _ := io.ReadAll(tc)
			got <- string(b)
			return
		}
		proxy{}.serve(tc)
	})
	_, port, _ := net.SplitHostPort(addr)
	for _, raw := range []string{"socks5s://alice:hunter2@127.0.0.1:", "socks5+tls://alice:hunter2@localhost:", "socks5h+tls://alice:hunter2@localhost:"} {
		d, err := socks0.FromURL(must(url.Parse(raw + port)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.DialContext(t.Context(), "tcp", "example.com:80")
		if he := handshakeErrOf(t, err); he.Stage != socks0.StageProxyDial {
			t.Fatalf("%s: err = %v", raw, err)
		}
		if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
			t.Errorf("%s: err = %v; want an unknown authority", raw, err)
		}
		if s := <-got; strings.Contains(s, "hunter2") {
			t.Fatalf("credentials reached the impostor: %s", s)
		}
	}
	p, err := socks0.ParseProxyURL(&url.URL{Scheme: "socks5+tls", Host: addr})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(must(x509.ParseCertificate(der)))
	d := &socks0.Dialer{ProxyAddr: p.Addr, Config: &p.Config, ProxyDial: (&tls.Dialer{Config: &tls.Config{RootCAs: pool}}).DialContext}
	c := mustDial(t, d, "tcp", "example.com:80")
	if _, ok := c.(*tls.Conn); !ok {
		t.Errorf("conn is %T", c)
	}
	c.Write([]byte("tls"))
	if s := readN(t, c, 3); s != "tls" {
		t.Errorf("echo %q", s)
	}
}

// tokenAuth holds a secret and has no LogValue.
type tokenAuth string

func (tokenAuth) Method() wire.Method                               { return 0x80 }
func (tokenAuth) Authenticate(context.Context, io.ReadWriter) error { return nil }

// Formatting a ProxyURL, Config, UserPass or Dialer, or logging them with slog, hides the password.
func TestFormattingRedactsPassword(t *testing.T) {
	u := must(url.Parse("socks5h://alice:hunter2@proxy.example:1080"))
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := d.DialContext(ctx, "tcp", "x:1")
	outs := map[string]string{
		"%v ProxyURL": fmt.Sprintf("%v", p), "%+v ProxyURL": fmt.Sprintf("%+v", p), "%#v ProxyURL": fmt.Sprintf("%#v", p),
		"%v Config": fmt.Sprintf("%v", *d.Config), "%+v *Config": fmt.Sprintf("%+v", d.Config), "%#v Config": fmt.Sprintf("%#v", *d.Config),
		"%v UserPass": fmt.Sprintf("%v", up), "%+v UserPass": fmt.Sprintf("%+v", up), "%#v UserPass": fmt.Sprintf("%#v", up),
		"%s": fmt.Sprintf("%s", up), "%q": fmt.Sprintf("%q", up), "%x": fmt.Sprintf("%x", up), "%d": fmt.Sprintf("%d", up),
		"%+v *UserPass in Config": fmt.Sprintf("%+v", *cfgPtr), "%#v *UserPass in Config": fmt.Sprintf("%#v", *cfgPtr),
		"%+v *Dialer": fmt.Sprintf("%+v", d), "err": fmt.Sprint(dialErr),
		"slog text": text.String(), "slog json": js.String(),
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
