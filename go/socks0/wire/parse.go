package wire

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

// ParseGreeting appends the offered methods to dst, allocating nothing if dst has room for 255.
func ParseGreeting(dst []Method, b []byte) (methods []Method, n int, err error) {
	switch err := checkVersion(b, Version5, StageGreeting); {
	case err != nil:
		return dst, 0, err
	case len(b) < 2:
		return dst, 3, ErrIncomplete
	case b[1] == 0:
		return dst, 0, &ProtocolError{Stage: StageGreeting, Field: FieldNMETHODS}
	}
	if n = 2 + int(b[1]); len(b) < n {
		return dst, n, ErrIncomplete
	}
	for _, m := range b[2:n] {
		dst = append(dst, Method(m))
	}
	return dst, n, nil
}

// ParseUserPass parses the RFC 1929 request; user and pass alias b.
func ParseUserPass(b []byte) (user, pass []byte, n int, err error) {
	if err := checkVersion(b, UserPassVersion, StageUserPass); err != nil {
		return nil, nil, 0, err
	}
	if len(b) < 2 {
		return nil, nil, 3, ErrIncomplete
	}
	plenAt := 2 + int(b[1])
	if len(b) <= plenAt {
		return nil, nil, plenAt + 1, ErrIncomplete
	}
	if n = plenAt + 1 + int(b[plenAt]); len(b) < n {
		return nil, nil, n, ErrIncomplete
	}
	return b[2:plenAt:plenAt], b[plenAt+1 : n : n], n, nil
}

// ParseRequest accepts any CMD; RSV is ignored.
func ParseRequest(b []byte) (cmd Command, addr Addr, n int, err error) {
	if err := checkVersion(b, Version5, StageRequest); err != nil {
		return 0, Addr{}, 0, err
	}
	if addr, n, err = parseAddrMessage(b, StageRequest, false); err != nil {
		return 0, Addr{}, n, err
	}
	return Command(b[1]), addr, n, nil
}

// ParseRequest4 parses SOCKS4 and 4a (DSTIP 0.0.0.x, x ≠ 0); userID aliases b. Awaiting
// a NUL, n is only a few bytes past b: read what the stream has and parse again.
func ParseRequest4(b []byte) (cmd Command, addr Addr, userID []byte, n int, err error) {
	if err := checkVersion(b, Version4, StageRequest4); err != nil {
		return 0, Addr{}, nil, 0, err
	}
	if len(b) < 8 {
		return 0, Addr{}, nil, 9, ErrIncomplete
	}
	is4a := isSOCKS4aIP([4]byte(b[4:])) && b[7] != 0
	afterUserID := 0
	if is4a {
		afterUserID = 2 // a name byte and its NUL
	}
	if userID, n, err = cstring(b, 8, FieldUSERID, 0, afterUserID); err != nil {
		return 0, Addr{}, nil, n, err
	}
	addr.port = binary.BigEndian.Uint16(b[2:])
	if !is4a {
		addr.ip = netip.AddrFrom4([4]byte(b[4:]))
		return Command(b[1]), addr, userID, n, nil
	}
	name, n, err := cstring(b, n, FieldADDR, 1, 0)
	if err != nil {
		return 0, Addr{}, nil, n, err
	}
	addr.name = string(name)
	return Command(b[1]), addr, userID, n, nil
}

func cstring(b []byte, start int, field string, minLen, after int) (s []byte, end int, err error) {
	i := bytes.IndexByte(b[start:], 0)
	switch {
	case i > 255, i < 0 && len(b)-start > 255, i >= 0 && i < minLen:
		return nil, 0, &ProtocolError{Stage: StageRequest4, Field: field}
	case i < 0:
		lacking := max(minLen-(len(b)-start), 0)
		return nil, len(b) + lacking + 1 + after, ErrIncomplete
	}
	return b[start : start+i : start+i], start + i + 1, nil
}

// ParseMethodSelection returns MethodNoAcceptable as a result, not an error.
func ParseMethodSelection(b []byte) (m Method, n int, err error) {
	switch err := checkVersion(b, Version5, StageMethodSelection); {
	case err != nil:
		return 0, 0, err
	case len(b) < 2:
		return 0, 2, ErrIncomplete
	}
	return Method(b[1]), 2, nil
}

// ParseUserPassStatus returns a non-zero status as a result, not an error.
func ParseUserPassStatus(b []byte) (status uint8, n int, err error) {
	switch err := checkVersion(b, UserPassVersion, StageUserPassStatus); {
	case err != nil:
		return 0, 0, err
	case len(b) < 2:
		return 0, 2, ErrIncomplete
	}
	return b[1], 2, nil
}

// ParseReply sets rep once b holds a good VER and REP, even on error. ATYP 0x00 (Tor's
// RESOLVE failure) is accepted, as the zero bound, only for the Tor RESOLVE commands.
func ParseReply(b []byte, cmd Command) (rep Reply, bound Addr, n int, err error) {
	if err := checkVersion(b, Version5, StageReply); err != nil {
		return 0, Addr{}, 0, err
	}
	if len(b) > 1 {
		rep = Reply(b[1])
	}
	bound, n, err = parseAddrMessage(b, StageReply, cmd == CmdTorResolve || cmd == CmdTorResolvePTR)
	return rep, bound, n, err
}

// ParseReply4 sets rep (CD) once b holds a good VN and CD, even on error.
func ParseReply4(b []byte) (rep Reply, bound Addr, n int, err error) {
	if err := checkVersion(b, 0, StageReply4); err != nil {
		return 0, Addr{}, 0, err
	}
	if len(b) > 1 {
		rep = Reply(b[1])
	}
	if len(b) < reply4Len {
		return rep, Addr{}, reply4Len, ErrIncomplete
	}
	return rep, Addr{ip: netip.AddrFrom4([4]byte(b[4:])), port: binary.BigEndian.Uint16(b[2:])}, reply4Len, nil
}

const reply4Len = 8

// ParseUDPHeader leaves the payload in b[n:]; ErrIncomplete means a truncated datagram.
func ParseUDPHeader(b []byte) (frag uint8, addr Addr, n int, err error) {
	if addr, n, err = parseAddrMessage(b, StageUDPHeader, false); err != nil {
		return 0, Addr{}, n, err
	}
	return b[2], addr, n, nil
}

func parseAddrMessage(b []byte, stage string, allowATYP0 bool) (Addr, int, error) {
	const throughDomainLen = 5 // never past a message: the shortest has 8 bytes
	if len(b) < 4 {
		return Addr{}, throughDomainLen, ErrIncomplete
	}
	var n int
	switch t := ATYP(b[3]); {
	case t == ATYPIPv4, t == 0 && allowATYP0:
		n = 3 + 1 + 4 + 2
	case t == ATYPIPv6:
		n = 3 + 1 + 16 + 2
	case t != ATYPDomain:
		return Addr{}, 0, &ProtocolError{Stage: stage, Field: FieldATYP, Got: b[3]}
	case len(b) < throughDomainLen:
		return Addr{}, throughDomainLen, ErrIncomplete
	case b[4] == 0:
		return Addr{}, 0, &ProtocolError{Stage: stage, Field: FieldADDR}
	default:
		n = 3 + 1 + 1 + int(b[4]) + 2
	}
	if len(b) < n {
		return Addr{}, n, ErrIncomplete
	}
	port := binary.BigEndian.Uint16(b[n-2:])
	switch ATYP(b[3]) {
	case ATYPIPv4:
		return Addr{ip: netip.AddrFrom4([4]byte(b[4:])), port: port}, n, nil
	case ATYPIPv6:
		return Addr{ip: netip.AddrFrom16([16]byte(b[4:])).Unmap(), port: port}, n, nil
	case ATYPDomain:
		return Addr{name: string(b[5 : n-2]), port: port}, n, nil
	}
	return Addr{}, n, nil // ATYP 0
}
