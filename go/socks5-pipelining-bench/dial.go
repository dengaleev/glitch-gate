package main

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	zerortt "github.com/dengaleev/glitch-gate/go/socks5-0rtt-pipelining"
	"github.com/txthinking/socks5"
)

// mode selects how the SOCKS5 tunnel is brought up before the application
// (TLS/HTTP) sends its first byte.
type mode int

const (
	modeRegular   mode = iota // sequential RFC 1928 handshake
	modePipelined             // greeting+auth+CONNECT coalesced into one write
	modeZeroRTT               // 0-RTT data pipelining (handshake + first payload in one write)
	modeZeroRTTFO             // 0-RTT data pipelining carried in the TCP SYN (TCP Fast Open)
)

func (m mode) String() string {
	switch m {
	case modeRegular:
		return "regular"
	case modePipelined:
		return "pipelined"
	case modeZeroRTT:
		return "0-rtt"
	case modeZeroRTTFO:
		return "0-rtt+tfo"
	default:
		return "?"
	}
}

// deferred reports whether the mode defers the SOCKS5 handshake into the first
// application write (so the per-phase SOCKS5 column is ~0 and the handshake
// cost folds into the TLS/TTFB measurement).
func (m mode) deferred() bool { return m == modeZeroRTT || m == modeZeroRTTFO }

// socks5Handshake does a SOCKS5 CONNECT to target on an already-connected proxy
// conn. The sequential path is byte-for-byte what socks5.Client.Dial sends; the
// pipelined path batches greeting+auth+request into one Write, saving 1-2 round
// trips. Batching is safe only because the client advertises a single auth
// method, so the reply is predictable and the request never depends on it.
func socks5Handshake(conn net.Conn, user, pass, target string, pipelined bool) error {
	method := socks5.MethodNone
	if user != "" {
		method = socks5.MethodUsernamePassword
	}

	atyp, addr, port, err := socks5.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse target %q: %w", target, err)
	}
	if atyp == socks5.ATYPDomain {
		addr = addr[1:] // ParseAddress length-prefixes the domain; NewRequest re-adds it
	}

	greeting := socks5.NewNegotiationRequest([]byte{method})
	var auth *socks5.UserPassNegotiationRequest
	if method == socks5.MethodUsernamePassword {
		auth = socks5.NewUserPassNegotiationRequest([]byte(user), []byte(pass))
	}
	request := socks5.NewRequest(socks5.CmdConnect, atyp, addr, port)

	if pipelined {
		var buf bytes.Buffer
		_, _ = greeting.WriteTo(&buf)
		if auth != nil {
			_, _ = auth.WriteTo(&buf)
		}
		_, _ = request.WriteTo(&buf)
		if _, err := conn.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write handshake: %w", err)
		}
		if err := readNegotiation(conn, method); err != nil {
			return err
		}
		if auth != nil {
			if err := readAuth(conn); err != nil {
				return err
			}
		}
		return readReply(conn)
	}

	if _, err := greeting.WriteTo(conn); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}
	if err := readNegotiation(conn, method); err != nil {
		return err
	}
	if auth != nil {
		if _, err := auth.WriteTo(conn); err != nil {
			return fmt.Errorf("write auth: %w", err)
		}
		if err := readAuth(conn); err != nil {
			return err
		}
	}
	if _, err := request.WriteTo(conn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	return readReply(conn)
}

func readNegotiation(conn net.Conn, method byte) error {
	rep, err := socks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if rep.Method != method {
		return fmt.Errorf("server selected method 0x%02x, expected 0x%02x", rep.Method, method)
	}
	return nil
}

func readAuth(conn net.Conn) error {
	rep, err := socks5.NewUserPassNegotiationReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read auth status: %w", err)
	}
	if rep.Status != socks5.UserPassStatusSuccess {
		return fmt.Errorf("authenticate: %w", socks5.ErrUserPassAuth)
	}
	return nil
}

func readReply(conn net.Conn) error {
	rep, err := socks5.NewReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if rep.Rep != socks5.RepSuccess {
		return fmt.Errorf("connect rejected (rep=0x%02x)", rep.Rep)
	}
	return nil
}

// makeDialContext returns a DialContext that dials the SOCKS5 proxy, tunnels to
// target per the given mode, and records the proxy DNS/TCP/handshake timestamps
// into pt. The proxy hostname is resolved once here (timed as DNS) so that for
// every mode the destination is handed to the proxy to resolve.
//
// For the deferred modes (0-rtt, 0-rtt+tfo) the SOCKS5 handshake is not
// performed here — it rides along with the first application write — so the
// SOCKS5 phase is ~0 and its cost folds into the TLS/TTFB measurement. That is
// the whole point, and TTFB/TTLB is the metric to compare across modes.
func makeDialContext(px *url.URL, m mode, timeout time.Duration, pt *phaseTrace) func(context.Context, string, string) (net.Conn, error) {
	user := px.User.Username()
	pass, _ := px.User.Password()
	host := px.Hostname()
	port := cmp.Or(px.Port(), "1080")

	return func(ctx context.Context, _ /*network*/, target string) (net.Conn, error) {
		ip := host
		if net.ParseIP(host) == nil {
			pt.dnsStart = time.Now()
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			pt.dnsDone = time.Now()
			if err != nil {
				return nil, fmt.Errorf("resolve proxy host %q: %w", host, err)
			}
			ip = addrs[0].IP.String()
		}
		proxyAddr := net.JoinHostPort(ip, port)

		if m.deferred() {
			d := &zerortt.Dialer{
				ProxyAddress: proxyAddr,
				Username:     user,
				Password:     pass,
				FastOpen:     m == modeZeroRTTFO,
				// Bound the connect explicitly: a FastOpen Conn dials lazily on
				// first write, after the request's dial context may already be
				// canceled, so a Conn deadline cannot reach that connect.
				NetDialer: &net.Dialer{Timeout: timeout},
			}
			pt.connStart = time.Now()
			conn, err := d.DialContext(ctx, "tcp", target)
			// A non-fast-open dialer connects eagerly here; a fast-open dialer
			// defers the connect to the first write. Either way the SOCKS5
			// handshake is deferred, so socksDone == connDone.
			pt.connDone = time.Now()
			pt.socksDone = pt.connDone
			if err != nil {
				return nil, err
			}
			return conn, nil
		}

		pt.connStart = time.Now()
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", proxyAddr)
		pt.connDone = time.Now()
		if err != nil {
			return nil, fmt.Errorf("connect proxy %s: %w", proxyAddr, err)
		}
		if err := socks5Handshake(conn, user, pass, target, m == modePipelined); err != nil {
			_ = conn.Close()
			return nil, err
		}
		pt.socksDone = time.Now()
		return conn, nil
	}
}
