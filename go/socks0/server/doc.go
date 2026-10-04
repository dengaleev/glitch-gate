// Package server is a SOCKS5 server (RFC 1928, RFC 1929) with optional SOCKS4/4a and Tor
// RESOLVE, shaped like net/http.
//
// It cannot lose pipelined (L1) or early (L2) client bytes: only the server reads the conn during
// the handshake, consuming each message by its parsed length, and Request.Reply returns a *Conn
// with every byte read past the request in front of it. Buffered bytes are dropped only when no
// target exists and on a UDP ASSOCIATE control conn. The zero Server serves SOCKS5 CONNECT
// without auth to public addresses only (DefaultFilter), with safe limits (../DESIGN.md §4–5):
//
//	s := &server.Server{Auth: []server.Authenticator{server.UserPass{Users: users}}}
//	go s.ListenAndServe()
//	defer s.Shutdown(ctx)
//
// Goroutines: one per Serve, one per conn, one more during Relay, two more per UDP association.
package server
