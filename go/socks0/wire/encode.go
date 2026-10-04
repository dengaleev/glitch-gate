package wire

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

func AppendGreeting(dst []byte, methods ...Method) ([]byte, error) {
	if len(methods) == 0 || len(methods) > 255 {
		return dst, fmt.Errorf("%w: %d methods", ErrInvalid, len(methods))
	}
	dst = append(slices.Grow(dst, 2+len(methods)), Version5, byte(len(methods)))
	for _, m := range methods {
		dst = append(dst, byte(m))
	}
	return dst, nil
}

func AppendUserPass(dst []byte, user, pass string) ([]byte, error) {
	if len(user) > 255 || len(pass) > 255 {
		return dst, fmt.Errorf("%w: username or password over 255 bytes", ErrInvalid)
	}
	dst = append(slices.Grow(dst, 3+len(user)+len(pass)), UserPassVersion, byte(len(user)))
	dst = append(dst, user...)
	return append(append(dst, byte(len(pass))), pass...), nil
}

func AppendRequest(dst []byte, cmd Command, addr Addr) ([]byte, error) {
	return appendAddrMessage(dst, [3]byte{Version5, byte(cmd), 0}, addr)
}

// AppendRequest4 sends a name as SOCKS4a; IPv6, 0.0.0.0/24 and NUL bytes are invalid.
func AppendRequest4(dst []byte, cmd Command, addr Addr, userID string) ([]byte, error) {
	if err := checkRequest4(addr, userID); err != nil {
		return dst, err
	}
	dstIP := [4]byte{0, 0, 0, 1} // SOCKS4a: the name follows USERID
	if addr.ip.Is4() {
		dstIP = addr.ip.As4()
	}
	dst = slices.Grow(dst, 8+len(userID)+1+len(addr.name)+1)
	dst = append(binary.BigEndian.AppendUint16(append(dst, Version4, byte(cmd)), addr.port), dstIP[:]...)
	dst = append(append(dst, userID...), 0)
	if addr.name != "" {
		dst = append(append(dst, addr.name...), 0)
	}
	return dst, nil
}

func checkRequest4(addr Addr, userID string) error {
	switch {
	case !addr.IsValid():
		return errZeroAddr
	case addr.ip.Is6():
		return fmt.Errorf("%w: SOCKS4 has no IPv6", ErrInvalid)
	case addr.ip.Is4() && isSOCKS4aIP(addr.ip.As4()):
		return fmt.Errorf("%w: SOCKS4 to 0.0.0.0/24", ErrInvalid)
	case len(userID) > 255 || strings.ContainsRune(userID, 0) || strings.ContainsRune(addr.name, 0):
		return fmt.Errorf("%w: USERID over 255 bytes, or a NUL byte", ErrInvalid)
	}
	return nil
}

func isSOCKS4aIP(ip [4]byte) bool { return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 }

func AppendMethodSelection(dst []byte, m Method) []byte { return append(dst, Version5, byte(m)) }

// AppendUserPassStatus: status 0 grants access.
func AppendUserPassStatus(dst []byte, status uint8) []byte {
	return append(dst, UserPassVersion, status)
}

func AppendReply(dst []byte, rep Reply, bound Addr) ([]byte, error) {
	return appendAddrMessage(dst, [3]byte{Version5, byte(rep), 0}, bound)
}

// AppendReply4 takes an IPv4 bound or the zero Addr (sent as 0.0.0.0:0).
func AppendReply4(dst []byte, rep Reply, bound Addr) ([]byte, error) {
	if bound.name != "" || bound.ip.Is6() {
		return dst, fmt.Errorf("%w: SOCKS4 reply to %v", ErrInvalid, bound)
	}
	var ip [4]byte
	if bound.ip.Is4() {
		ip = bound.ip.As4()
	}
	return append(binary.BigEndian.AppendUint16(append(dst, 0, byte(rep)), bound.port), ip[:]...), nil
}

func AppendUDPHeader(dst []byte, frag uint8, addr Addr) ([]byte, error) {
	return appendAddrMessage(dst, [3]byte{0, 0, frag}, addr)
}

// UDPHeaderLen returns 0 for the zero Addr.
func UDPHeaderLen(a Addr) int {
	if !a.IsValid() {
		return 0
	}
	return 3 + a.wireLen()
}

const MaxUDPHeaderLen = 3 + 1 + 1 + 255 + 2

func appendAddrMessage(dst []byte, header [3]byte, addr Addr) ([]byte, error) {
	if !addr.IsValid() {
		return dst, errZeroAddr
	}
	return addr.append(append(slices.Grow(dst, len(header)+addr.wireLen()), header[0], header[1], header[2])), nil
}
