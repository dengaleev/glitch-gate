// Package wire is a SOCKS codec for both sides: SOCKS5 (RFC 1928), RFC 1929
// username/password, Tor's extensions (RESOLVE, F0–F7 replies) and SOCKS4/4a.
//
// Append* fail only on fields that do not fit the wire, wrapping [ErrInvalid]; dst is then unchanged.
//
// Parse* parse one message at the start of b. On success n is its length and
// only a domain name's string is allocated. On [ErrIncomplete] b is a valid
// prefix and len(b) < n ≤ the message length: call again once b holds n bytes.
// Any other error is a [*ProtocolError] with n == 0; errors in the bytes present
// win over incompleteness. On error the other results are meaningless, except
// rep of [ParseReply] and [ParseReply4].
//
// Read* read exactly one message, never more; a stream ending mid-message is a
// [*ProtocolError] wrapping [io.ErrUnexpectedEOF]. Codes are open: unknown
// values are kept and print in hex.
package wire

const (
	Version5        = 0x05
	Version4        = 0x04 // SOCKS4 requests; replies have 0
	UserPassVersion = 0x01 // RFC 1929
)

// MaxReplyLen is the longest reply or request: a 255-byte domain name.
const MaxReplyLen = 4 + 1 + 255 + 2
