package wire

import (
	"errors"
	"strings"
)

var (
	// ErrIncomplete means b holds a valid but incomplete message.
	ErrIncomplete = errors.New("wire: incomplete message")

	// ErrInvalid is wrapped by Append* errors: a field over 255 bytes, 0 or 256+ methods,
	// or the zero Addr.
	ErrInvalid = errors.New("wire: invalid field")
)

// Messages: the values of [ProtocolError.Stage].
const (
	StageGreeting        = "greeting"
	StageMethodSelection = "method selection"
	StageUserPass        = "username/password request"
	StageUserPassStatus  = "username/password status"
	StageRequest         = "request"
	StageReply           = "reply"
	StageUDPHeader       = "udp header"
	StageRequest4        = "socks4 request"
	StageReply4          = "socks4 reply"
)

// Fields: the values of [ProtocolError.Field].
const (
	FieldVER      = "VER"
	FieldNMETHODS = "NMETHODS" // 0
	FieldATYP     = "ATYP"     // unknown, or 0x00 outside a RESOLVE reply
	FieldADDR     = "ADDR"     // empty domain name
	FieldPORT     = "PORT"     // BND.PORT 0 where a port is required (UDP relay, BIND)
	FieldUSERID   = "USERID"   // SOCKS4: over 255 bytes
)

// ProtocolError reports a malformed or truncated message.
type ProtocolError struct {
	Stage string // a Stage constant
	Field string // a Field constant; "" when truncated
	Got   uint8  // the offending byte
	Hint  string // a likely cause, or ""
	Err   error  // the cause if any, e.g. io.ErrUnexpectedEOF
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return "<nil>"
	}
	parts := []string{"socks " + e.Stage}
	if strings.HasPrefix(e.Stage, "socks4 ") {
		parts[0] = e.Stage
	}
	if e.Field != "" {
		parts = append(parts, "invalid "+e.Field+" "+hexCode(e.Got))
	}
	if e.Hint != "" {
		parts[len(parts)-1] += " (" + e.Hint + ")"
	}
	if e.Err != nil {
		parts = append(parts, e.Err.Error())
	}
	if len(parts) == 1 {
		parts = append(parts, "malformed")
	}
	return strings.Join(parts, ": ")
}

func (e *ProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

const (
	hintHTTP   = "likely an HTTP proxy"
	hintSOCKS4 = "likely a SOCKS4 server"
	hintTor    = "Tor rejected the username format"
	hintSOCKS5 = "likely a SOCKS5-only server"
)

func checkVersion(b []byte, want uint8, stage string) error {
	if len(b) == 0 || b[0] == want {
		return nil
	}
	return &ProtocolError{Stage: stage, Field: FieldVER, Got: b[0], Hint: versionHint(stage, b[0])}
}

func versionHint(stage string, ver uint8) string {
	switch stage {
	case StageReply4:
		switch ver {
		case 'H':
			return hintHTTP
		case Version5:
			return hintSOCKS5
		}
	case StageMethodSelection, StageUserPassStatus, StageReply:
		switch {
		case ver == 'H':
			return hintHTTP
		case ver == 0:
			return hintSOCKS4
		case ver == Version5 && stage == StageUserPassStatus:
			return hintTor
		}
	}
	return ""
}
