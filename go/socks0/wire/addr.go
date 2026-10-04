package wire

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Addr is an IP or 1–255 byte domain name, and a port; the zero Addr is invalid. It compares
// as sent: an IP is unmapped and zone-free; a name is never resolved or parsed as an IP.
type Addr struct {
	ip   netip.Addr
	name string
	port uint16
}

// ParseAddr takes a decimal port. An IP host is unmapped, a zone is an error; any other
// 1–255 byte host is a name, sent as is. Errors are [*net.AddrError].
func ParseAddr(hostport string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Addr{}, err
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Addr{}, &net.AddrError{Err: "invalid port", Addr: hostport}
	}
	port := uint16(p)
	if hostport[0] == '[' {
		ip, err := netip.ParseAddr(host)
		switch {
		case err != nil || !ip.Is6():
			return Addr{}, &net.AddrError{Err: "brackets need an IPv6 address", Addr: hostport}
		case ip.Zone() != "":
			return Addr{}, &net.AddrError{Err: "IPv6 zone not allowed", Addr: hostport}
		}
		return Addr{ip: ip.Unmap(), port: port}, nil
	}
	if strings.Trim(host, "0123456789.") == "" {
		if ip, err := netip.ParseAddr(host); err == nil {
			return Addr{ip: ip, port: port}, nil
		}
	}
	if len(host) == 0 || len(host) > 255 {
		return Addr{}, &net.AddrError{Err: "host must be 1-255 bytes", Addr: hostport}
	}
	return Addr{name: host, port: port}, nil
}

// AddrFromAddrPort unmaps ap and drops any zone; an invalid ap gives the zero Addr.
func AddrFromAddrPort(ap netip.AddrPort) Addr {
	if !ap.IsValid() {
		return Addr{}
	}
	return Addr{ip: ap.Addr().Unmap().WithZone(""), port: ap.Port()}
}

func (a Addr) IP() netip.Addr { return a.ip }

func (a Addr) Name() string { return a.name }

func (a Addr) Port() uint16 { return a.port }

func (a Addr) IsName() bool { return a.name != "" }

func (a Addr) IsValid() bool { return a.ip.IsValid() || a.name != "" }

// ATYP returns 0 for the zero Addr.
func (a Addr) ATYP() ATYP {
	switch {
	case a.name != "":
		return ATYPDomain
	case a.ip.Is4():
		return ATYPIPv4
	case a.ip.Is6():
		return ATYPIPv6
	}
	return 0
}

func (a Addr) String() string {
	switch {
	case a.name != "":
		return net.JoinHostPort(a.name, strconv.Itoa(int(a.port)))
	case a.ip.IsValid():
		return netip.AddrPortFrom(a.ip, a.port).String()
	}
	return "invalid Addr"
}

// Network returns "socks".
func (a Addr) Network() string { return "socks" }

// AppendBinary appends ATYP, ADDR and PORT; it fails only for the zero Addr.
func (a Addr) AppendBinary(b []byte) ([]byte, error) {
	if !a.IsValid() {
		return b, errZeroAddr
	}
	return a.append(b), nil
}

var errZeroAddr = fmt.Errorf("%w: zero Addr", ErrInvalid)

func (a Addr) wireLen() int {
	switch {
	case a.name != "":
		return 1 + 1 + len(a.name) + 2
	case a.ip.Is4():
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

func (a Addr) append(b []byte) []byte {
	b = append(b, byte(a.ATYP()))
	if a.name != "" {
		b = append(append(b, byte(len(a.name))), a.name...)
	} else {
		b, _ = a.ip.AppendBinary(b) // zone-free: never fails
	}
	return binary.BigEndian.AppendUint16(b, a.port)
}
