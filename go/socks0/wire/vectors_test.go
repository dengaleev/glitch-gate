package wire

import "io"

// codec adapts one message type to a common shape for table tests.
type codec struct {
	stage  string
	encode func(dst []byte, v any) ([]byte, error)
	parse  func(b []byte) (v any, n int, err error)
	read   func(r io.Reader) (v any, err error) // nil for datagrams
}

type (
	userPassV struct{ user, pass string }
	cmdAddr   struct {
		cmd  Command
		addr Addr
	}
	repAddr struct {
		rep  Reply
		addr Addr
	}
	fragAddr struct {
		frag uint8
		addr Addr
	}
	request4V struct {
		cmd  Command
		addr Addr
		user string
	}
)

var (
	greeting = codec{StageGreeting,
		func(dst []byte, v any) ([]byte, error) { return AppendGreeting(dst, v.([]Method)...) },
		func(b []byte) (any, int, error) { m, n, err := ParseGreeting(nil, b); return m, n, err },
		func(r io.Reader) (any, error) { m, err := ReadGreeting(r); return m, err },
	}
	userPass = codec{StageUserPass,
		func(dst []byte, v any) ([]byte, error) {
			up := v.(userPassV)
			return AppendUserPass(dst, up.user, up.pass)
		},
		func(b []byte) (any, int, error) {
			u, p, n, err := ParseUserPass(b)
			return userPassV{string(u), string(p)}, n, err
		},
		func(r io.Reader) (any, error) {
			u, p, err := ReadUserPass(r)
			return userPassV{string(u), string(p)}, err
		},
	}
	request = codec{StageRequest,
		func(dst []byte, v any) ([]byte, error) { return AppendRequest(dst, v.(cmdAddr).cmd, v.(cmdAddr).addr) },
		func(b []byte) (any, int, error) { c, a, n, err := ParseRequest(b); return cmdAddr{c, a}, n, err },
		func(r io.Reader) (any, error) { c, a, err := ReadRequest(r); return cmdAddr{c, a}, err },
	}
	selection = codec{StageMethodSelection,
		func(dst []byte, v any) ([]byte, error) { return AppendMethodSelection(dst, v.(Method)), nil },
		func(b []byte) (any, int, error) { return ParseMethodSelection(b) },
		func(r io.Reader) (any, error) { return ReadMethodSelection(r) },
	}
	status = codec{StageUserPassStatus,
		func(dst []byte, v any) ([]byte, error) { return AppendUserPassStatus(dst, v.(uint8)), nil },
		func(b []byte) (any, int, error) { return ParseUserPassStatus(b) },
		func(r io.Reader) (any, error) { return ReadUserPassStatus(r) },
	}
	udp = codec{StageUDPHeader,
		func(dst []byte, v any) ([]byte, error) {
			return AppendUDPHeader(dst, v.(fragAddr).frag, v.(fragAddr).addr)
		},
		func(b []byte) (any, int, error) { f, a, n, err := ParseUDPHeader(b); return fragAddr{f, a}, n, err },
		nil,
	}
	request4 = codec{StageRequest4,
		func(dst []byte, v any) ([]byte, error) {
			r := v.(request4V)
			return AppendRequest4(dst, r.cmd, r.addr, r.user)
		},
		func(b []byte) (any, int, error) {
			c, a, u, n, err := ParseRequest4(b)
			return request4V{c, a, string(u)}, n, err
		},
		func(r io.Reader) (any, error) {
			c, a, u, err := ReadRequest4(r)
			return request4V{c, a, string(u)}, err
		},
	}
	reply4 = codec{StageReply4,
		func(dst []byte, v any) ([]byte, error) { return AppendReply4(dst, v.(repAddr).rep, v.(repAddr).addr) },
		func(b []byte) (any, int, error) { r, a, n, err := ParseReply4(b); return repAddr{r, a}, n, err },
		func(r io.Reader) (any, error) { rep, a, err := ReadReply4(r); return repAddr{rep, a}, err },
	}
	replyConnect = reply(CmdConnect)
	replyResolve = reply(CmdTorResolve)
	replyPTR     = reply(CmdTorResolvePTR)
)

func reply(cmd Command) codec {
	return codec{StageReply,
		func(dst []byte, v any) ([]byte, error) { return AppendReply(dst, v.(repAddr).rep, v.(repAddr).addr) },
		func(b []byte) (any, int, error) { r, a, n, err := ParseReply(b, cmd); return repAddr{r, a}, n, err },
		func(r io.Reader) (any, error) { rep, a, err := ReadReply(r, cmd); return repAddr{rep, a}, err },
	}
}

type vector struct {
	c            codec
	name         string
	b            []byte
	want         any
	nonCanonical bool // b is not want's encoding: RSV, mapped IPv6, ATYP 0
}

var mappedBin = msg(4, make([]byte, 10), 0xff, 0xff, 192, 0, 2, 1, 0x04, 0x38) // ::ffff:192.0.2.1

func valid() []vector {
	all, allBin := make([]Method, 255), make([]byte, 255)
	for i := range all {
		all[i], allBin[i] = Method(i), byte(i)
	}
	longDom := Addr{name: long, port: 1}
	tor1234 := Addr{name: "1.2.3.4", port: 80}
	return []vector{
		{greeting, "one", msg(5, 1, 0), []Method{MethodNoAuth}, false},
		{greeting, "two", msg(5, 2, 0, 2), []Method{MethodNoAuth, MethodUserPass}, false},
		{greeting, "255", msg(5, 255, allBin), all, false},

		{userPass, "user pass", msg(1, 4, "user", 4, "pass"), userPassV{"user", "pass"}, false},
		{userPass, "empty", msg(1, 0, 0), userPassV{}, false},
		{userPass, "empty user", msg(1, 0, 3, "abc"), userPassV{"", "abc"}, false},
		{userPass, "empty pass", msg(1, 1, "u", 0), userPassV{"u", ""}, false},
		{userPass, "255", msg(1, 255, long, 255, long), userPassV{long, long}, false},

		{request, "IPv4", msg(5, 1, 0, v4Bin), cmdAddr{CmdConnect, v4}, false},
		{request, "IPv6", msg(5, 1, 0, v6Bin), cmdAddr{CmdConnect, v6}, false},
		{request, "domain", msg(5, 1, 0, domBin), cmdAddr{CmdConnect, dom}, false},
		{request, "domain 255", msg(5, 2, 0, 3, 255, long, 0, 1), cmdAddr{CmdBind, longDom}, false},
		{request, "domain 1.2.3.4", msg(5, 1, 0, 3, 7, "1.2.3.4", 0, 80), cmdAddr{CmdConnect, tor1234}, false},
		{request, "resolve", msg(5, 0xF0, 0, domBin), cmdAddr{CmdTorResolve, dom}, false},
		{request, "unknown CMD", msg(5, 0x7F, 0, v4Bin), cmdAddr{0x7F, v4}, false},
		{request, "RSV", msg(5, 1, 0xFF, v4Bin), cmdAddr{CmdConnect, v4}, true},
		{request, "mapped", msg(5, 1, 0, mappedBin), cmdAddr{CmdConnect, v4}, true},

		{selection, "no auth", msg(5, 0), MethodNoAuth, false},
		{selection, "no acceptable", msg(5, 0xFF), MethodNoAcceptable, false},
		{selection, "private", msg(5, 0x80), Method(0x80), false},

		{status, "success", msg(1, 0), uint8(0), false},
		{status, "failure", msg(1, 1), uint8(1), false},
		{status, "0xff", msg(1, 0xFF), uint8(0xFF), false},

		{replyConnect, "IPv4", msg(5, 0, 0, v4Bin), repAddr{ReplySucceeded, v4}, false},
		{replyConnect, "IPv6", msg(5, 0, 0, v6Bin), repAddr{ReplySucceeded, v6}, false},
		{replyConnect, "domain", msg(5, 0, 0, domBin), repAddr{ReplySucceeded, dom}, false},
		{replyConnect, "domain 1.2.3.4", msg(5, 0, 0, 3, 7, "1.2.3.4", 0, 80), repAddr{0, tor1234}, false},
		{replyConnect, "refused", msg(5, 5, 0, v4Bin), repAddr{ReplyConnectionRefused, v4}, false},
		{replyConnect, "unknown REP", msg(5, 0x42, 0, v4Bin), repAddr{0x42, v4}, false},
		{replyConnect, "tor F6", msg(5, 0xF6, 0, v4Bin), repAddr{ReplyTorHSBadAddress, v4}, false},
		{replyConnect, "RSV", msg(5, 0, 0x01, v4Bin), repAddr{ReplySucceeded, v4}, true},
		{replyConnect, "mapped", msg(5, 0, 0, mappedBin), repAddr{ReplySucceeded, v4}, true},
		{replyResolve, "IPv4", msg(5, 0, 0, v4Bin), repAddr{ReplySucceeded, v4}, false},
		{replyResolve, "ATYP 0", msg(5, 4, 0, 0, 0, 0, 0, 0, 0, 0), repAddr{ReplyHostUnreachable, Addr{}}, true},
		{replyResolve, "ATYP 0 junk", msg(5, 1, 0, 0, 1, 2, 3, 4, 5, 6), repAddr{ReplyGeneralFailure, Addr{}}, true},
		{replyPTR, "domain", msg(5, 0, 0, domBin), repAddr{ReplySucceeded, dom}, false},
		{replyPTR, "ATYP 0", msg(5, 4, 0, 0, 0, 0, 0, 0, 0, 0), repAddr{ReplyHostUnreachable, Addr{}}, true},

		{udp, "IPv4", msg(0, 0, 0, v4Bin), fragAddr{0, v4}, false},
		{udp, "IPv6", msg(0, 0, 0, v6Bin), fragAddr{0, v6}, false},
		{udp, "domain frag", msg(0, 0, 7, domBin), fragAddr{7, dom}, false},
		{udp, "RSV", msg(0xAB, 0xCD, 0, v4Bin), fragAddr{0, v4}, true},

		{request4, "IPv4", msg(4, 1, 0x04, 0x38, 192, 0, 2, 1, 0), request4V{CmdConnect, v4, ""}, false},
		{request4, "USERID", msg(4, 1, 0x04, 0x38, 192, 0, 2, 1, "alice", 0), request4V{CmdConnect, v4, "alice"}, false},
		{request4, "USERID 255", msg(4, 1, 0x04, 0x38, 192, 0, 2, 1, long, 0), request4V{CmdConnect, v4, long}, false},
		{request4, "BIND", msg(4, 2, 0x04, 0x38, 192, 0, 2, 1, 0), request4V{CmdBind, v4, ""}, false},
		{request4, "4a", msg(4, 1, 0, 80, 0, 0, 0, 1, "u", 0, "example.com", 0), request4V{CmdConnect, dom, "u"}, false},
		{request4, "4a no USERID", msg(4, 1, 0, 80, 0, 0, 0, 1, 0, "example.com", 0), request4V{CmdConnect, dom, ""}, false},
		{request4, "4a 255", msg(4, 1, 0, 1, 0, 0, 0, 1, long, 0, long, 0), request4V{CmdConnect, longDom, long}, false},
		{request4, "4a 0.0.0.255", msg(4, 1, 0, 80, 0, 0, 0, 255, 0, "example.com", 0), request4V{CmdConnect, dom, ""}, true},
		{request4, "DSTIP 0", msg(4, 2, 0, 0, 0, 0, 0, 0, 0), request4V{CmdBind, mustAddr("0.0.0.0:0"), ""}, true},
		{request4, "unknown CMD", msg(4, 0x7F, 0x04, 0x38, 192, 0, 2, 1, 0), request4V{0x7F, v4, ""}, false},

		{reply4, "granted", msg(0, 0x5A, 0, 0, 0, 0, 0, 0), repAddr{Reply4Granted, mustAddr("0.0.0.0:0")}, false},
		{reply4, "rejected", msg(0, 0x5B, 0x04, 0x38, 192, 0, 2, 1), repAddr{Reply4Rejected, v4}, false},
		{reply4, "unknown CD", msg(0, 0x42, 0, 0, 0, 0, 0, 0), repAddr{0x42, mustAddr("0.0.0.0:0")}, false},
	}
}

type badVector struct {
	c    codec
	name string
	b    []byte
	want ProtocolError
}

func malformed() []badVector {
	ver := func(stage string, got uint8, hint string) ProtocolError {
		return ProtocolError{Stage: stage, Field: FieldVER, Got: got, Hint: hint}
	}
	atyp := func(stage string, got uint8) ProtocolError {
		return ProtocolError{Stage: stage, Field: FieldATYP, Got: got}
	}
	empty := func(stage string) ProtocolError { return ProtocolError{Stage: stage, Field: FieldADDR} }
	return []badVector{
		{greeting, "SOCKS4", msg(4, 1, 0), ver(StageGreeting, 4, "")},
		{greeting, "HTTP", msg("GET / HTTP/1.1"), ver(StageGreeting, 'G', "")},
		{greeting, "H", msg('H'), ver(StageGreeting, 'H', "")},
		{greeting, "NMETHODS 0", msg(5, 0), ProtocolError{Stage: StageGreeting, Field: FieldNMETHODS}},
		{greeting, "NMETHODS 0 more", msg(5, 0, 1, 2), ProtocolError{Stage: StageGreeting, Field: FieldNMETHODS}},

		{userPass, "VER 5", msg(5, 1, 0), ver(StageUserPass, 5, "")},
		{userPass, "VER 0", msg(0), ver(StageUserPass, 0, "")},

		{request, "VER", msg(4, 1, 0, v4Bin), ver(StageRequest, 4, "")},
		{request, "H", msg('H'), ver(StageRequest, 'H', "")},
		{request, "ATYP 0", msg(5, 0xF0, 0, 0), atyp(StageRequest, 0)},
		{request, "ATYP 2", msg(5, 1, 0, 2, 1, 2, 3, 4, 5, 6), atyp(StageRequest, 2)},
		{request, "ATYP ff", msg(5, 1, 0, 0xFF), atyp(StageRequest, 0xFF)},
		{request, "empty domain", msg(5, 1, 0, 3, 0, 0, 80), empty(StageRequest)},

		{selection, "HTTP", msg("HTTP/1.1 400 Bad Request"), ver(StageMethodSelection, 'H', hintHTTP)},
		{selection, "H", msg('H'), ver(StageMethodSelection, 'H', hintHTTP)},
		{selection, "SOCKS4", msg(0, 0x5B), ver(StageMethodSelection, 0, hintSOCKS4)},
		{selection, "VER 4", msg(4, 0), ver(StageMethodSelection, 4, "")},
		{selection, "VER 1", msg(1), ver(StageMethodSelection, 1, "")},

		{status, "Tor", msg(5, 1, 0, 1, 0, 0, 0, 0, 0, 0), ver(StageUserPassStatus, 5, hintTor)},
		{status, "Tor 1", msg(5), ver(StageUserPassStatus, 5, hintTor)},
		{status, "HTTP", msg("HTTP/1.0"), ver(StageUserPassStatus, 'H', hintHTTP)},
		{status, "SOCKS4", msg(0), ver(StageUserPassStatus, 0, hintSOCKS4)},
		{status, "VER 2", msg(2, 0), ver(StageUserPassStatus, 2, "")},

		{replyConnect, "HTTP", msg("HTTP/"), ver(StageReply, 'H', hintHTTP)},
		{replyConnect, "SOCKS4", msg(0, 0x5B, 0, 0, 0, 0, 0, 0), ver(StageReply, 0, hintSOCKS4)},
		{replyConnect, "VER 1", msg(1, 0), ver(StageReply, 1, "")},
		{replyConnect, "ATYP 0", msg(5, 0, 0, 0, 0, 0, 0, 0, 0, 0), atyp(StageReply, 0)},
		{replyConnect, "ATYP 5", msg(5, 0, 0, 5), atyp(StageReply, 5)},
		{replyConnect, "empty domain", msg(5, 0, 0, 3, 0), empty(StageReply)},
		{reply(CmdBind), "ATYP 0", msg(5, 0, 0, 0), atyp(StageReply, 0)},
		{reply(CmdUDPAssociate), "ATYP 0", msg(5, 0, 0, 0), atyp(StageReply, 0)},
		{replyResolve, "ATYP 2", msg(5, 0, 0, 2), atyp(StageReply, 2)},
		{replyPTR, "empty domain", msg(5, 0, 0, 3, 0, 0, 0), empty(StageReply)},

		{udp, "ATYP 0", msg(0, 0, 0, 0), atyp(StageUDPHeader, 0)},
		{udp, "ATYP 2", msg(0, 0, 0, 2, 1, 2, 3, 4, 5, 6), atyp(StageUDPHeader, 2)},
		{udp, "empty domain", msg(0, 0, 0, 3, 0), empty(StageUDPHeader)},

		{request4, "VER 5", msg(5, 1, 0, 80, 192, 0, 2, 1, 0), ver(StageRequest4, 5, "")},
		{request4, "USERID 256", msg(4, 1, 0, 80, 192, 0, 2, 1, long, 'a'), ProtocolError{Stage: StageRequest4, Field: FieldUSERID}},
		{request4, "4a USERID 256", msg(4, 1, 0, 80, 0, 0, 0, 1, long, 'a'), ProtocolError{Stage: StageRequest4, Field: FieldUSERID}},
		{request4, "4a empty name", msg(4, 1, 0, 80, 0, 0, 0, 1, 0, 0), empty(StageRequest4)},
		{request4, "4a name 256", msg(4, 1, 0, 80, 0, 0, 0, 1, 0, long, 'a'), empty(StageRequest4)},

		{reply4, "SOCKS5", msg(5, 0xFF), ver(StageReply4, 5, hintSOCKS5)},
		{reply4, "HTTP", msg("HTTP/1.1"), ver(StageReply4, 'H', hintHTTP)},
		{reply4, "VN 4", msg(4, 0x5A, 0, 0, 0, 0, 0, 0), ver(StageReply4, 4, "")},
	}
}
