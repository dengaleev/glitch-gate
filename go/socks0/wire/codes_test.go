package wire

import (
	"fmt"
	"io"
	"testing"
)

func TestCodeStrings(t *testing.T) {
	for _, tt := range []struct {
		code fmt.Stringer
		want string
	}{
		{MethodNoAuth, "no auth"},
		{MethodGSSAPI, "GSSAPI"},
		{MethodUserPass, "username/password"},
		{MethodCHAP, "CHAP"},
		{Method(0x04), "0x04"},
		{MethodCRAM, "CRAM"},
		{MethodSSL, "SSL"},
		{MethodNDS, "NDS"},
		{MethodMultiAuth, "multi-auth"},
		{MethodJSON, "JSON"},
		{Method(0x80), "0x80"},
		{MethodNoAcceptable, "no acceptable methods"},
		{CmdConnect, "CONNECT"},
		{CmdBind, "BIND"},
		{CmdUDPAssociate, "UDP ASSOCIATE"},
		{CmdTorResolve, "RESOLVE"},
		{CmdTorResolvePTR, "RESOLVE_PTR"},
		{Command(0), "0x00"},
		{ATYPIPv4, "IPv4"},
		{ATYPDomain, "domain"},
		{ATYPIPv6, "IPv6"},
		{ATYP(0), "0x00"},
		{ReplySucceeded, "succeeded"},
		{ReplyGeneralFailure, "general SOCKS server failure"},
		{ReplyNotAllowed, "connection not allowed by ruleset"},
		{ReplyNetworkUnreachable, "network unreachable"},
		{ReplyHostUnreachable, "host unreachable"},
		{ReplyConnectionRefused, "connection refused"},
		{ReplyTTLExpired, "TTL expired"},
		{ReplyCommandNotSupported, "command not supported"},
		{ReplyAddressTypeNotSupported, "address type not supported"},
		{Reply(0x09), "0x09"},
		{Reply(0xEF), "0xef"},
		{ReplyTorHSNotFound, "tor: onion service descriptor can not be found"},
		{ReplyTorHSInvalid, "tor: onion service descriptor is invalid"},
		{ReplyTorHSIntroFailed, "tor: onion service introduction failed"},
		{ReplyTorHSRendFailed, "tor: onion service rendezvous failed"},
		{ReplyTorHSMissingClientAuth, "tor: onion service missing client authorization"},
		{ReplyTorHSBadClientAuth, "tor: onion service wrong client authorization"},
		{ReplyTorHSBadAddress, "tor: onion service invalid address"},
		{ReplyTorHSIntroTimedOut, "tor: onion service introduction timed out"},
		{Reply(0xF8), "0xf8"},
	} {
		if got := tt.code.String(); got != tt.want {
			t.Errorf("%T(%#02x).String() = %q, want %q", tt.code, tt.code, got, tt.want)
		}
	}
}

func TestReply4String(t *testing.T) {
	for _, tt := range []struct {
		r    Reply
		want string
	}{
		{Reply4Granted, "request granted"},
		{Reply4Rejected, "request rejected or failed"},
		{Reply4NoIdentd, "cannot connect to identd"},
		{Reply4IdentMismatch, "identd user id mismatch"},
		{0x00, "0x00"},
		{0x5E, "0x5e"},
	} {
		if got := Reply4String(tt.r); got != tt.want {
			t.Errorf("Reply4String(%#02x) = %q, want %q", uint8(tt.r), got, tt.want)
		}
	}
	if Reply4Granted.String() != "0x5a" {
		t.Errorf("Reply.String is SOCKS5 only: %q", Reply4Granted.String())
	}
}

func TestMethodIsPrivate(t *testing.T) {
	for m := range 256 {
		if got, want := Method(m).IsPrivate(), m >= 0x80 && m <= 0xFE; got != want {
			t.Errorf("Method(%#02x).IsPrivate() = %v", m, got)
		}
	}
}

func TestProtocolErrorString(t *testing.T) {
	for _, tt := range []struct {
		e    ProtocolError
		want string
	}{
		{ProtocolError{Stage: StageMethodSelection, Field: FieldVER, Got: 'H', Hint: hintHTTP},
			"socks method selection: invalid VER 0x48 (likely an HTTP proxy)"},
		{ProtocolError{Stage: StageReply, Field: FieldATYP, Got: 7}, "socks reply: invalid ATYP 0x07"},
		{ProtocolError{Stage: StageReply, Err: io.ErrUnexpectedEOF}, "socks reply: unexpected EOF"},
		{ProtocolError{Stage: StageGreeting, Field: FieldVER, Got: 4, Err: io.EOF}, "socks greeting: invalid VER 0x04: EOF"},
		{ProtocolError{Stage: StageRequest}, "socks request: malformed"},
		{ProtocolError{Stage: StageReply4, Field: FieldVER, Got: 5, Hint: hintSOCKS5}, "socks4 reply: invalid VER 0x05 (likely a SOCKS5-only server)"},
	} {
		if got := tt.e.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
	if e := (&ProtocolError{Err: io.ErrUnexpectedEOF}); e.Unwrap() != io.ErrUnexpectedEOF {
		t.Error("Unwrap")
	}
	var nilErr *ProtocolError
	if nilErr.Error() != "<nil>" || nilErr.Unwrap() != nil {
		t.Error("nil *ProtocolError")
	}
}
