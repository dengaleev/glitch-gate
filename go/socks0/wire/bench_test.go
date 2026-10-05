package wire

import (
	"bytes"
	"testing"
)

func BenchmarkAppendHandshake(b *testing.B) {
	dst := make([]byte, 0, 64)
	for b.Loop() {
		buf, _ := AppendGreeting(dst, MethodUserPass)
		buf, _ = AppendUserPass(buf, "user", "pass")
		AppendRequest(buf, CmdConnect, dom)
	}
}

func BenchmarkAppendReply(b *testing.B) {
	dst := make([]byte, 0, 64)
	for b.Loop() {
		AppendReply(dst, ReplySucceeded, v6)
	}
}

func BenchmarkParseReply(b *testing.B) {
	for _, bm := range []struct {
		name string
		b    []byte
	}{
		{"IPv4", msg(5, 0, 0, v4Bin)},
		{"IPv6", msg(5, 0, 0, v6Bin)},
		{"domain", msg(5, 0, 0, domBin)},
	} {
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(bm.b)))
			for b.Loop() {
				ParseReply(bm.b, CmdConnect)
			}
		})
	}
}

func BenchmarkParseRequest(b *testing.B) {
	in := msg(5, 1, 0, v4Bin)
	for b.Loop() {
		ParseRequest(in)
	}
}

func BenchmarkParseGreeting(b *testing.B) {
	in, dst := msg(5, 2, 0, 2), make([]Method, 0, 255)
	for b.Loop() {
		ParseGreeting(dst, in)
	}
}

func BenchmarkParseUDPHeader(b *testing.B) {
	in := msg(0, 0, 0, v4Bin, "payload")
	for b.Loop() {
		ParseUDPHeader(in)
	}
}

func BenchmarkParseAddr(b *testing.B) {
	for b.Loop() {
		ParseAddr("[2001:db8::1]:443")
	}
}

func BenchmarkReadReply(b *testing.B) {
	in := msg(5, 0, 0, v4Bin)
	r := bytes.NewReader(in)
	for b.Loop() {
		r.Reset(in)
		ReadReply(r, CmdConnect)
	}
}
