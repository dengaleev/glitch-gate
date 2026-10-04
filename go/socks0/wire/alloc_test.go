package wire

import (
	"net/netip"
	"testing"
)

func TestAllocs(t *testing.T) {
	methods := make([]Method, 0, 255)
	dst := make([]byte, 0, 1024)
	ap := netip.MustParseAddrPort("[2001:db8::1]:443")
	greet, up, sel, st := msg(5, 2, 0, 2), msg(1, 1, "u", 1, "p"), msg(5, 0), msg(1, 0)
	reqV4, reqV6, reqDom := msg(5, 1, 0, v4Bin), msg(5, 1, 0, v6Bin), msg(5, 1, 0, domBin)
	repV4, repV6, repDom := msg(5, 0, 0, v4Bin), msg(5, 0, 0, v6Bin), msg(5, 0, 0, domBin)
	rep0, udpV6 := msg(5, 4, 0, 0, 0, 0, 0, 0, 0, 0), msg(0, 0, 0, v6Bin)
	req4, req4a, rep4 := msg(4, 1, 0, 80, 192, 0, 2, 1, "u", 0), msg(4, 1, 0, 80, 0, 0, 0, 1, 0, "example.com", 0), msg(0, 0x5A, 0, 0, 0, 0, 0, 0)
	for _, tt := range []struct {
		name string
		want float64
		f    func()
	}{
		{"ParseGreeting", 0, func() { ParseGreeting(methods, greet) }},
		{"ParseUserPass", 0, func() { ParseUserPass(up) }},
		{"ParseRequest IPv4", 0, func() { ParseRequest(reqV4) }},
		{"ParseRequest IPv6", 0, func() { ParseRequest(reqV6) }},
		{"ParseRequest domain", 1, func() { ParseRequest(reqDom) }},
		{"ParseMethodSelection", 0, func() { ParseMethodSelection(sel) }},
		{"ParseUserPassStatus", 0, func() { ParseUserPassStatus(st) }},
		{"ParseReply IPv4", 0, func() { ParseReply(repV4, CmdConnect) }},
		{"ParseReply IPv6", 0, func() { ParseReply(repV6, CmdConnect) }},
		{"ParseReply domain", 1, func() { ParseReply(repDom, CmdConnect) }},
		{"ParseReply ATYP 0", 0, func() { ParseReply(rep0, CmdTorResolve) }},
		{"ParseReply incomplete", 0, func() { ParseReply(sel, CmdConnect) }},
		{"ParseUDPHeader", 0, func() { ParseUDPHeader(udpV6) }},
		{"ParseAddr IP", 0, func() { ParseAddr("[2001:db8::1]:443") }},
		{"ParseAddr name", 0, func() { ParseAddr("example.com:443") }},
		{"AddrFromAddrPort", 0, func() { AddrFromAddrPort(ap) }},
		{"AppendGreeting", 0, func() { AppendGreeting(dst, MethodNoAuth, MethodUserPass) }},
		{"AppendUserPass", 0, func() { AppendUserPass(dst, "user", "pass") }},
		{"AppendRequest IPv6", 0, func() { AppendRequest(dst, CmdConnect, v6) }},
		{"AppendRequest domain", 0, func() { AppendRequest(dst, CmdConnect, dom) }},
		{"AppendMethodSelection", 0, func() { AppendMethodSelection(dst, MethodNoAuth) }},
		{"AppendUserPassStatus", 0, func() { AppendUserPassStatus(dst, 0) }},
		{"AppendReply IPv4", 0, func() { AppendReply(dst, ReplySucceeded, v4) }},
		{"AppendUDPHeader", 0, func() { AppendUDPHeader(dst, 0, v4) }},
		{"UDPHeaderLen", 0, func() { UDPHeaderLen(dom) }},
		{"AppendBinary", 0, func() { v6.AppendBinary(dst) }},
		{"ParseRequest4", 0, func() { ParseRequest4(req4) }},
		{"ParseRequest4 4a", 1, func() { ParseRequest4(req4a) }},
		{"ParseReply4", 0, func() { ParseReply4(rep4) }},
		{"AppendRequest4", 0, func() { AppendRequest4(dst, CmdConnect, dom, "user") }},
		{"AppendReply4", 0, func() { AppendReply4(dst, Reply4Granted, v4) }},
	} {
		if got := testing.AllocsPerRun(100, tt.f); got != tt.want {
			t.Errorf("%s: %v allocs, want %v", tt.name, got, tt.want)
		}
	}
}
