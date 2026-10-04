package socks0

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProxyURL is a parsed proxy URL; formatted or logged it shows no password.
type ProxyURL struct {
	Addr           string // "host:port"; port defaults to 1080
	Config         Config // Auth from the userinfo; Version 4 for socks4, socks4a
	ResolveLocally bool   // socks5://, socks4:// (curl): see FromURL
	TLS            bool   // socks5s://, socks5+tls://, socks5h+tls://: ServerName = host
}

func (p ProxyURL) LogValue() slog.Value {
	return slog.GroupValue(slog.String("addr", p.Addr), slog.Any("config", p.Config),
		slog.Bool("resolve_locally", p.ResolveLocally), slog.Bool("tls", p.TLS))
}

// ParseProxyURL parses socks5 (local DNS, as curl: a leak), socks5h, socks5s,
// socks5+tls, socks5h+tls, socks4 (local DNS) and socks4a URLs. Userinfo
// becomes a UserPass even if empty. Errors show only scheme and host.
func ParseProxyURL(u *url.URL) (*ProxyURL, error) {
	if u == nil {
		return nil, errors.New("socks0: nil proxy URL")
	}
	p := new(ProxyURL)
	if why := p.parse(u); why != "" {
		// Not u.Redacted: user names can hold tokens, and it keeps Opaque.
		shown := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
		return nil, errors.New("socks0: proxy URL " + strconv.Quote(shown) + ": " + why)
	}
	return p, nil
}

func (p *ProxyURL) parse(u *url.URL) (why string) {
	if !p.setScheme(u.Scheme) {
		return "unsupported scheme"
	}
	switch {
	case u.Opaque != "":
		return "opaque"
	case u.Hostname() == "":
		return "no host"
	}
	port, ok := normalizePort(u.Port())
	if !ok {
		return "port must be 1-65535"
	}
	p.Addr = net.JoinHostPort(u.Hostname(), port)
	if host, _, err := net.SplitHostPort(p.Addr); err != nil || host != u.Hostname() {
		return "invalid host"
	}
	if u.User != nil {
		return p.setUser(u.User)
	}
	return ""
}

func (p *ProxyURL) setScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "socks5":
		p.ResolveLocally = true
	case "socks5h":
	case "socks5s", "socks5+tls", "socks5h+tls":
		p.TLS = true
	case "socks4":
		p.ResolveLocally, p.Config.Version = true, 4
	case "socks4a":
		p.Config.Version = 4
	default:
		return false
	}
	return true
}

func normalizePort(port string) (string, bool) {
	if port == "" {
		return "1080", true
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}

func (p *ProxyURL) setUser(user *url.Userinfo) (why string) {
	pass, _ := user.Password()
	if len(user.Username()) > 255 || len(pass) > 255 {
		return "username or password over 255 bytes"
	}
	if p.Config.Version == 4 && pass != "" {
		return "SOCKS4 has no password"
	}
	p.Config.Auth = UserPass{Username: user.Username(), Password: pass}
	return ""
}

// FromURL returns a Dialer for a proxy URL with curl semantics. Security:
// socks5:// and socks4:// resolve target names locally (net.DefaultResolver),
// a DNS leak that can deanonymize Tor users, unlike net/http and x/net/proxy;
// use socks5h://. TLS schemes verify the proxy's certificate; userinfo is
// cleartext otherwise, sent before the proxy answers in ModePipelined.
func FromURL(u *url.URL) (*Dialer, error) {
	p, err := ParseProxyURL(u)
	if err != nil {
		return nil, err
	}
	d := &Dialer{ProxyAddr: p.Addr, Config: &p.Config}
	if p.ResolveLocally {
		d.Resolver = net.DefaultResolver
	}
	if p.TLS {
		d.ProxyDial = new(tls.Dialer).DialContext
	}
	return d, nil
}
