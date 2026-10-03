// Package s5 is a minimal client-side SOCKS5 codec (RFC 1928/1929) and echo
// target, shared by the server checks and the reference client.
package s5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	MethodNone     = 0x00
	MethodUserPass = 0x02
)

const (
	socksVersion = 5
	authVersion  = 1
	cmdConnect   = 1
	atypIPv4     = 1
	atypDomain   = 3
	atypIPv6     = 4
)

// Method is the one auth method a client commits to: user/pass if user is
// set, else none. A single method makes replies predictable, so pipelining
// is safe.
func Method(user string) byte {
	if user != "" {
		return MethodUserPass
	}
	return MethodNone
}

// Greeting advertises Method(user) only.
func Greeting(user string) []byte { return []byte{socksVersion, 1, Method(user)} }

// Auth is the RFC 1929 username/password request.
func Auth(user, pass string) []byte {
	b := []byte{authVersion, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

// Connect is a CONNECT request; ATYP is IPv4, IPv6 or domain by host.
func Connect(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", portStr, err)
	}
	b := []byte{socksVersion, cmdConnect, 0}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		if len(host) > 255 {
			return nil, errors.New("domain too long")
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	case ip.To4() != nil:
		b = append(append(b, atypIPv4), ip.To4()...)
	default:
		b = append(append(b, atypIPv6), ip.To16()...)
	}
	return append(b, byte(port>>8), byte(port)), nil
}

// Handshake is greeting + [auth] + CONNECT: a pipelining (L1) client's
// single write.
func Handshake(user, pass, target string) ([]byte, error) {
	req, err := Connect(target)
	if err != nil {
		return nil, err
	}
	b := Greeting(user)
	if user != "" {
		b = append(b, Auth(user, pass)...)
	}
	return append(b, req...), nil
}

// ReadReplies reads the method selection, the auth status (if user is set)
// and the CONNECT reply, and nothing past it.
func ReadReplies(r io.Reader, user string) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if b[0] != socksVersion || b[1] != Method(user) {
		return fmt.Errorf("method selection %x, want 05%02x", b, Method(user))
	}
	if user != "" {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return fmt.Errorf("read auth status: %w", err)
		}
		if b[1] != 0 {
			return fmt.Errorf("auth rejected (status 0x%02x)", b[1])
		}
	}
	return ReadConnectReply(r)
}

// ReadConnectReply reads a whole CONNECT reply and fails unless REP is success.
func ReadConnectReply(r io.Reader) error {
	var h [5]byte // VER REP RSV ATYP, BND.ADDR[0] (domain: its length)
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if h[0] != socksVersion || h[1] != 0 {
		return fmt.Errorf("connect rejected (ver 0x%02x, rep 0x%02x)", h[0], h[1])
	}
	var addrLeft int
	switch h[3] {
	case atypIPv4:
		addrLeft = net.IPv4len - 1
	case atypIPv6:
		addrLeft = net.IPv6len - 1
	case atypDomain:
		addrLeft = int(h[4])
	default:
		return fmt.Errorf("connect reply: bad atyp 0x%02x", h[3])
	}
	const portLen = 2
	if _, err := io.ReadFull(r, make([]byte, addrLeft+portLen)); err != nil {
		return fmt.Errorf("read connect reply address: %w", err)
	}
	return nil
}

// Echo serves a TCP echo on ln until ln is closed.
func Echo(ln net.Listener) {
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
}
