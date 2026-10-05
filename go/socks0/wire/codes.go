package wire

import "fmt"

// Method is an authentication method (IANA "SOCKS Methods").
type Method uint8

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodUserPass     Method = 0x02 // RFC 1929
	MethodCHAP         Method = 0x03 // challenge-handshake authentication protocol
	MethodCRAM         Method = 0x05 // challenge-response authentication method
	MethodSSL          Method = 0x06
	MethodNDS          Method = 0x07
	MethodMultiAuth    Method = 0x08 // multi-authentication framework
	MethodJSON         Method = 0x09 // JSON parameter block
	MethodNoAcceptable Method = 0xFF
)

// IsPrivate reports whether m is in the private range 0x80–0xFE.
func (m Method) IsPrivate() bool { return m >= 0x80 && m <= 0xFE }

func (m Method) String() string {
	switch m {
	case MethodNoAuth:
		return "no auth"
	case MethodGSSAPI:
		return "GSSAPI"
	case MethodUserPass:
		return "username/password"
	case MethodCHAP:
		return "CHAP"
	case MethodCRAM:
		return "CRAM"
	case MethodSSL:
		return "SSL"
	case MethodNDS:
		return "NDS"
	case MethodMultiAuth:
		return "multi-auth"
	case MethodJSON:
		return "JSON"
	case MethodNoAcceptable:
		return "no acceptable methods"
	}
	return hexCode(uint8(m))
}

type Command uint8

const (
	CmdConnect       Command = 0x01
	CmdBind          Command = 0x02
	CmdUDPAssociate  Command = 0x03
	CmdTorResolve    Command = 0xF0 // name → address
	CmdTorResolvePTR Command = 0xF1 // address → name
)

func (c Command) String() string {
	switch c {
	case CmdConnect:
		return "CONNECT"
	case CmdBind:
		return "BIND"
	case CmdUDPAssociate:
		return "UDP ASSOCIATE"
	case CmdTorResolve:
		return "RESOLVE"
	case CmdTorResolvePTR:
		return "RESOLVE_PTR"
	}
	return hexCode(uint8(c))
}

type ATYP uint8

const (
	ATYPIPv4   ATYP = 0x01
	ATYPDomain ATYP = 0x03
	ATYPIPv6   ATYP = 0x04
)

func (a ATYP) String() string {
	switch a {
	case ATYPIPv4:
		return "IPv4"
	case ATYPDomain:
		return "domain"
	case ATYPIPv6:
		return "IPv6"
	}
	return hexCode(uint8(a))
}

// Reply is the REP field; 0xF0–0xF7 are Tor proposal 304 onion service errors.
type Reply uint8

const (
	ReplySucceeded               Reply = 0x00
	ReplyGeneralFailure          Reply = 0x01
	ReplyNotAllowed              Reply = 0x02 // by ruleset
	ReplyNetworkUnreachable      Reply = 0x03
	ReplyHostUnreachable         Reply = 0x04
	ReplyConnectionRefused       Reply = 0x05
	ReplyTTLExpired              Reply = 0x06
	ReplyCommandNotSupported     Reply = 0x07
	ReplyAddressTypeNotSupported Reply = 0x08

	ReplyTorHSNotFound          Reply = 0xF0 // descriptor not found
	ReplyTorHSInvalid           Reply = 0xF1 // descriptor invalid
	ReplyTorHSIntroFailed       Reply = 0xF2 // introduction failed
	ReplyTorHSRendFailed        Reply = 0xF3 // rendezvous failed
	ReplyTorHSMissingClientAuth Reply = 0xF4 // client authorization missing
	ReplyTorHSBadClientAuth     Reply = 0xF5 // client authorization wrong
	ReplyTorHSBadAddress        Reply = 0xF6 // invalid onion address
	ReplyTorHSIntroTimedOut     Reply = 0xF7 // introduction timed out
)

// SOCKS4 CD codes; they do not collide with SOCKS5's, but only Reply4String names them.
const (
	Reply4Granted       Reply = 0x5A
	Reply4Rejected      Reply = 0x5B // rejected or failed
	Reply4NoIdentd      Reply = 0x5C // cannot connect to identd
	Reply4IdentMismatch Reply = 0x5D // identd user id mismatch
)

func Reply4String(r Reply) string {
	if r >= Reply4Granted && int(r-Reply4Granted) < len(reply4Names) {
		return reply4Names[r-Reply4Granted]
	}
	return hexCode(uint8(r))
}

func (r Reply) String() string {
	switch {
	case int(r) < len(replyNames):
		return replyNames[r]
	case r >= ReplyTorHSNotFound && int(r-ReplyTorHSNotFound) < len(torReplyNames):
		return torReplyNames[r-ReplyTorHSNotFound]
	}
	return hexCode(uint8(r))
}

var (
	replyNames = [...]string{
		ReplySucceeded:               "succeeded",
		ReplyGeneralFailure:          "general SOCKS server failure",
		ReplyNotAllowed:              "connection not allowed by ruleset",
		ReplyNetworkUnreachable:      "network unreachable",
		ReplyHostUnreachable:         "host unreachable",
		ReplyConnectionRefused:       "connection refused",
		ReplyTTLExpired:              "TTL expired",
		ReplyCommandNotSupported:     "command not supported",
		ReplyAddressTypeNotSupported: "address type not supported",
	}
	reply4Names = [...]string{ // from Reply4Granted
		"request granted",
		"request rejected or failed",
		"cannot connect to identd",
		"identd user id mismatch",
	}
	torReplyNames = [...]string{ // from ReplyTorHSNotFound
		"tor: onion service descriptor can not be found",
		"tor: onion service descriptor is invalid",
		"tor: onion service introduction failed",
		"tor: onion service rendezvous failed",
		"tor: onion service missing client authorization",
		"tor: onion service wrong client authorization",
		"tor: onion service invalid address",
		"tor: onion service introduction timed out",
	}
)

func hexCode(b uint8) string { return fmt.Sprintf("0x%02x", b) }
