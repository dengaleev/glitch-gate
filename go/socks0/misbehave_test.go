package socks0_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func reply(rep wire.Reply, bound string) []byte {
	b, _ := wire.AppendReply(nil, rep, mustAddr(bound))
	return b
}

func TestMisbehavingServers(t *testing.T) {
	userPass := socks0.UserPass{Username: "user", Password: "secret"}
	torReply := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0} // Tor answers a bad username format with a SOCKS5 reply
	for _, tt := range []struct {
		name  string
		resp  []byte
		auth  socks0.Authenticator
		stage string
		kind  socks0.Kind
		str   string
		is    []error
	}{
		{
			name: "no acceptable methods", resp: []byte{5, 0xFF},
			stage: wire.StageMethodSelection, kind: socks0.KindMethod, is: []error{socks0.ErrNoAcceptableMethods},
			str: "socks method selection: no acceptable methods (offered no auth)",
		},
		{
			name: "no acceptable methods userpass", resp: []byte{5, 0xFF}, auth: userPass,
			stage: wire.StageMethodSelection, kind: socks0.KindMethod, is: []error{socks0.ErrNoAcceptableMethods},
			str: "socks method selection: no acceptable methods (offered username/password)",
		},
		{
			name: "method not offered", resp: []byte{5, 2},
			stage: wire.StageMethodSelection, kind: socks0.KindMethod, is: []error{socks0.ErrMethodNotOffered},
			str: "socks method selection: server selected username/password, offered no auth",
		},
		{
			name: "auth rejected", resp: []byte{5, 2, 1, 1}, auth: userPass,
			stage: wire.StageUserPassStatus, kind: socks0.KindAuth, is: []error{socks0.ErrAuthFailed},
			str: "socks auth: rejected (username/password status 0x01)",
		},
		{
			name: "connection refused", resp: append([]byte{5, 0}, reply(5, "0.0.0.0:0")...),
			stage: wire.StageReply, kind: socks0.KindReply, is: []error{eConnRefused},
			str: "socks reply: connection refused",
		},
		{
			name: "command not supported", resp: append([]byte{5, 0}, reply(7, "0.0.0.0:0")...),
			stage: wire.StageReply, kind: socks0.KindReply, is: []error{errors.ErrUnsupported},
			str: "socks reply: command not supported",
		},
		{
			name: "unknown reply", resp: append([]byte{5, 0}, reply(0x5b, "0.0.0.0:0")...),
			stage: wire.StageReply, kind: socks0.KindReply, str: "socks reply: 0x5b",
		},
		{
			name: "tor reply", resp: append([]byte{5, 0}, reply(0xF6, "0.0.0.0:0")...),
			stage: wire.StageReply, kind: socks0.KindReply, str: "socks reply: tor: onion service invalid address",
		},
		{
			name: "refused, malformed tail", resp: []byte{5, 0, 5, 5, 0, 9, 9, 9},
			stage: wire.StageReply, kind: socks0.KindReply, is: []error{eConnRefused},
			str: "socks reply: connection refused",
		},
		{
			name: "refused, truncated", resp: []byte{5, 0, 5, 5, 0, 1, 1},
			stage: wire.StageReply, kind: socks0.KindReply, is: []error{eConnRefused},
			str: "socks reply: connection refused",
		},
		{
			name: "bad ATYP", resp: []byte{5, 0, 5, 0, 0, 9, 9, 9},
			stage: wire.StageReply, kind: socks0.KindProtocol,
			str: "socks reply: invalid ATYP 0x09",
		},
		{
			name: "truncated reply", resp: []byte{5, 0, 5, 0, 0, 1, 1, 2},
			stage: wire.StageReply, kind: socks0.KindEOF, is: []error{io.ErrUnexpectedEOF},
			str: "socks reply: unexpected EOF",
		},
		{
			name: "HTTP proxy", resp: []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
			stage: wire.StageMethodSelection, kind: socks0.KindProtocol,
			str: "socks method selection: invalid VER 0x48 (likely an HTTP proxy)",
		},
		{
			name: "SOCKS4 server", resp: []byte{0, 0x5b, 0, 0, 0, 0, 0, 0},
			stage: wire.StageMethodSelection, kind: socks0.KindProtocol,
			str: "socks method selection: invalid VER 0x00 (likely a SOCKS4 server)",
		},
		{
			name: "Tor rejects username", resp: append([]byte{5, 2}, torReply...), auth: userPass,
			stage: wire.StageUserPassStatus, kind: socks0.KindProtocol,
			str: "socks username/password status: invalid VER 0x05 (Tor rejected the username format)",
		},
		{
			name: "closed at once", resp: nil,
			stage: wire.StageMethodSelection, kind: socks0.KindEOF, is: []error{io.ErrUnexpectedEOF},
			str: "socks method selection: unexpected EOF",
		},
		{
			name: "closed after method", resp: []byte{5, 2}, auth: userPass,
			stage: wire.StageUserPassStatus, kind: socks0.KindEOF, is: []error{io.ErrUnexpectedEOF},
			str: "socks username/password status: unexpected EOF",
		},
		{
			name: "closed after auth", resp: []byte{5, 2, 1, 0}, auth: userPass,
			stage: wire.StageReply, kind: socks0.KindEOF, is: []error{io.ErrUnexpectedEOF},
			str: "socks reply: unexpected EOF",
		},
	} {
		for _, mode := range modes {
			t.Run(tt.name+"/"+mode.String(), func(t *testing.T) {
				var replies []string
				cfg := &socks0.Config{Mode: mode, Auth: tt.auth, Trace: &socks0.ClientTrace{
					GotReply: func(rep wire.Reply, bound wire.Addr) { replies = append(replies, fmt.Sprint(rep, bound)) },
				}}
				d := &socks0.Dialer{ProxyAddr: listen(t, scripted(tt.resp, false)), Config: cfg}
				err := handshakeErr(t.Context(), d, "example.com:80")
				he := handshakeErrOf(t, err)
				if he.Stage != tt.stage {
					t.Errorf("stage %q, want %q", he.Stage, tt.stage)
				}
				if k := socks0.KindOf(err); k != tt.kind {
					t.Errorf("KindOf = %q, want %q", k, tt.kind)
				}
				if s := he.Error(); s != tt.str {
					t.Errorf("Error() = %q\nwant       %q", s, tt.str)
				}
				for _, target := range tt.is {
					if target != nil && !errors.Is(err, target) {
						t.Errorf("err does not match %v", target)
					}
				}
				if pe, ok := errors.AsType[*socks0.ProtocolError](err); ok && pe.Stage != he.Stage {
					t.Errorf("ProtocolError.Stage %q", pe.Stage)
				}
				re, isReply := errors.AsType[*socks0.ReplyError](err)
				if isReply != (len(replies) == 1) || len(replies) > 1 {
					t.Errorf("GotReply ran for %v", replies)
				}
				if isReply && re.Bound.IsValid() != (tt.kind == socks0.KindReply && !slices.Contains([]string{"refused, malformed tail", "refused, truncated"}, tt.name)) {
					t.Errorf("Bound = %v", re.Bound)
				}
				if op := err.(*net.OpError); op.Timeout() {
					t.Error("Timeout() = true")
				}
			})
		}
	}
}
