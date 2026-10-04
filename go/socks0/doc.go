// Package socks0 is a SOCKS5 client (RFC 1928/1929; also SOCKS4/4a and Tor
// extensions) that can pipeline the handshake and send early data.
//
// Modes ([Config.Mode]), never mixed or fallen back between:
//   - [ModePipelined] (L1, default): whole handshake in one write; errors from DialContext.
//   - [ModeSequential] (L0): a round trip per message, as RFC 1928.
//   - [ModeEarly] (L2): handshake rides with the first Write; errors from the first Read.
//
// Layers:
//   - [Dialer]: TCP, UDP, BIND and Tor RESOLVE via a proxy; fits http.Transport, x/net/proxy.
//   - [Client], [Request]: the handshake over any conn, like tls.Client.
//   - package wire: every message, both directions.
//
// As an http.Transport dialer:
//
//	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
//	tr := &http.Transport{DialContext: d.DialContext}
//
// Migrating from x/net/proxy or net/http:
//   - errno: a [*ReplyError] matches errno (REP 04 is EHOSTUNREACH); use [KindOf] to tell them apart.
//   - Mode: default is [ModePipelined]; probes use [ModeSequential], never [ModeEarly].
//   - URLs: [FromURL] socks5:// resolves locally (DNS leak); use socks5h://, always for Tor.
//   - Timeouts: [Config.HandshakeTimeout] is 30 s unless ctx has a deadline; negative is none.
//
// See DESIGN.md.
package socks0
